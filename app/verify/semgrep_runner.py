"""Semgrep rule runner."""

import json
import subprocess
from pathlib import Path

import yaml

from app.schema import Emit


RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
REGISTRY_FILE = RULES_DIR / "registry.yaml"


def load_registry(emit: Emit) -> dict[str, str]:
    """Load advisory ID to rule file mapping."""
    if not REGISTRY_FILE.exists():
        emit("verification", "info", "No rules registry found", None)
        return {}

    try:
        data = yaml.safe_load(REGISTRY_FILE.read_text()) or {}
        return data.get("advisories", {})
    except Exception as e:
        emit("verification", "warn", f"Failed to load registry: {e}", None)
        return {}


def run_semgrep(
    repo_path: str,
    advisory_ids: list[str],
    registry: dict[str, str],
    emit: Emit,
) -> dict[str, dict]:
    """Run Semgrep rules for matching advisories."""
    results = {}

    # Find rules for these advisories
    rule_files = []
    advisory_to_rule = {}

    for aid in advisory_ids:
        rule_file = registry.get(aid)
        if rule_file:
            rule_path = RULES_DIR / rule_file
            if rule_path.exists():
                rule_files.append(str(rule_path))
                advisory_to_rule[aid] = rule_file

    if not rule_files:
        emit("verification", "info", "No Semgrep rules mapped for these advisories", None)
        return results

    emit("verification", "info", f"Running {len(rule_files)} Semgrep rules", None)

    try:
        # Run Semgrep once with all rules
        cmd = [
            "semgrep", "scan",
            "--json",
            "--metrics=off",
            "--timeout", "30",
        ]
        for rf in rule_files:
            cmd.extend(["--config", rf])
        cmd.append(repo_path)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode not in (0, 1):  # 0 = no findings, 1 = findings
            emit("verification", "warn", f"Semgrep failed: {result.stderr[:200]}", None)
            # Signal error so callers can produce inconclusive status
            return {"_error": {"detail": f"Semgrep exited {result.returncode}", "source_url": None}}

        # Parse results
        try:
            output = json.loads(result.stdout)
            findings = output.get("results", [])

            emit("verification", "info", f"Semgrep found {len(findings)} hits", None)

            for finding in findings:
                rule_id = finding.get("check_id", "")
                path = finding.get("path", "")
                line = finding.get("start", {}).get("line", 0)
                message = finding.get("extra", {}).get("message", "")

                # Find advisory ID from rule metadata
                metadata = finding.get("extra", {}).get("metadata", {})
                advisory_id = metadata.get("advisory_id")

                if advisory_id:
                    results[advisory_id] = {
                        "detail": f"Semgrep rule {rule_id} matched {path}:{line}: {message}",
                        "source_url": f"file://{path}#L{line}",
                    }

        except json.JSONDecodeError as e:
            emit("verification", "warn", f"Failed to parse Semgrep output: {e}", None)
            return {"_error": {"detail": f"Failed to parse Semgrep output: {e}", "source_url": None}}

    except subprocess.TimeoutExpired:
        emit("verification", "warn", "Semgrep timed out", None)
        return {"_error": {"detail": "Semgrep timed out", "source_url": None}}
    except FileNotFoundError:
        emit("verification", "warn", "Semgrep not installed", None)
        return {"_error": {"detail": "Semgrep not installed", "source_url": None}}
    except Exception as e:
        emit("verification", "warn", f"Semgrep error: {e}", None)
        return {"_error": {"detail": f"Semgrep error: {e}", "source_url": None}}

    return results

