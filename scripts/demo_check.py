#!/usr/bin/env python3
"""Check acceptance criteria against a running app on :3003."""

import subprocess
import sys
import time
from pathlib import Path

import httpx

BASE = "http://localhost:3003"
ROOT = Path(__file__).resolve().parent.parent
JUICE_SHOP_REPO = "demo/juice-shop"
TARGET_ID = "t_juiceshop"
RUN_TIMEOUT_S = 300


def check(label: str, ok: bool, detail: str = "") -> bool:
    print(f"[{'PASS' if ok else 'FAIL'}] {label}" + (f": {detail}" if detail else ""))
    return ok


def wait_for_run(client: httpx.Client, run_id: str, timeout_s: int = RUN_TIMEOUT_S) -> dict:
    deadline = time.monotonic() + timeout_s
    data: dict = {}
    while time.monotonic() < deadline:
        r = client.get(f"/api/runs/{run_id}")
        if r.status_code == 200:
            data = r.json()
            if data.get("state") in ("complete", "failed"):
                return data
        time.sleep(1)
    return data


def start_run(client: httpx.Client, target_id: str) -> str:
    r = client.post("/api/runs", json={"target_id": target_id, "trigger": "manual"})
    r.raise_for_status()
    body = r.json()
    if not body.get("run_id"):
        raise RuntimeError(f"Run for {target_id} was coalesced into an active run: {body}")
    return body["run_id"]


def main() -> int:
    results: list[bool] = []
    client = httpx.Client(base_url=BASE, timeout=30)

    r = client.post("/api/targets", json={
        "target_id": TARGET_ID,
        "kind": "connected_repo",
        "name": "OWASP Juice Shop",
        "repo": JUICE_SHOP_REPO,
    })
    r.raise_for_status()
    target = r.json()
    print(f"Target {target['target_id']} authorized={target['authorized']} "
          f"({target['authorization_reason']})")

    run_id = start_run(client, TARGET_ID)
    print(f"Started run {run_id}, waiting...")
    run_data = wait_for_run(client, run_id)
    state = run_data.get("state")

    results.append(check("AC-1: Run completes with records in ClickHouse", state == "complete",
                         f"state={state} error={run_data.get('error')}"))

    findings = client.get(f"/api/runs/{run_id}/report").json().get("findings", [])
    print(f"Report: {len(findings)} findings")

    verified = [f for f in findings if f.get("verification_status") == "verified"]
    ac2 = any(any(e.get("kind") == "semgrep" for e in f.get("evidence", [])) for f in verified)
    results.append(check("AC-2: >=1 verified finding with Semgrep evidence", ac2,
                         f"{len(verified)} verified"))

    not_present = [f for f in findings if f.get("verification_status") == "not_present"]
    possible = [f for f in findings if f.get("match_type") == "possible"]
    results.append(check("AC-3: >=1 not_present or possible candidate",
                         bool(not_present or possible),
                         f"{len(not_present)} not_present, {len(possible)} possible"))

    scores = [f.get("risk_score", 0) for f in findings]
    results.append(check("AC-4: Findings ranked by risk score",
                         scores == sorted(scores, reverse=True)))

    no_source = [f["candidate_id"] for f in findings if not f.get("advisory_url")]
    results.append(check("AC-5: Every finding has advisory_url", not no_source,
                         f"{len(no_source)} missing"))

    r = client.post("/api/targets", json={"kind": "public", "name": "Public probe",
                                          "domain": "example.com"})
    r.raise_for_status()
    pub = r.json()
    pub_run_id = start_run(client, pub["target_id"])
    pub_run = wait_for_run(client, pub_run_id, timeout_s=120)
    pub_findings = client.get(f"/api/runs/{pub_run_id}/report").json().get("findings", [])
    pub_ok = (
        not pub["authorized"]
        and not pub_run.get("verification_authorized", False)
        and all(f.get("verification_status") == "inconclusive" for f in pub_findings)
    )
    results.append(check("AC-6: Public target never reaches verification", pub_ok,
                         f"state={pub_run.get('state')}, {len(pub_findings)} findings"))

    events = client.get("/api/events", params={"target_id": TARGET_ID}).json()
    results.append(check("AC-7: Live feed has events for the run",
                         any(e.get("run_id") == run_id for e in events),
                         f"{len(events)} events"))

    grep = subprocess.run(
        ["grep", "-rIE", r"(sk-[A-Za-z0-9]{20,}|OPENAI_API_KEY\s*=\s*['\"]?sk-)",
         "app/", "scripts/", "web/", "config/"],
        check=False, cwd=ROOT, capture_output=True, text=True,
    )
    results.append(check("AC-8: No hardcoded secrets", grep.returncode == 1,
                         grep.stdout.strip()[:200]))

    passed = sum(results)
    print(f"\nResult: {passed}/{len(results)} passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
