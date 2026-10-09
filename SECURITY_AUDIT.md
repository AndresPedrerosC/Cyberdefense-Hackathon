# Security Audit: Continuous Exposure Agent (FastAPI backend)

**Date:** 2026-10-09
**Scope:** `app/**/*.py`, `config/demo.yaml`, `docker-compose.yml`, `.env.example`. The `stackwatch/` Next.js app and `web/` front end are out of scope.
**Method:** Manual source review from an attacker's perspective (unauthenticated network caller), with regression tests for each fixed issue.

## Summary

| ID  | Severity | Finding | Status |
|-----|----------|---------|--------|
| H-1 | High     | Target ID spoofing and hijacking through a caller-chosen `target_id` | **Fixed** |
| H-2 | High     | `repo` lets a caller point discovery at any server path (filesystem read, `copytree` DoS, `npm` run on attacker-chosen dir) | **Fixed** |
| H-3 | High     | No authentication on any endpoint; guessable run IDs give IDOR on reports and events | Open |
| H-4 | High     | ClickHouse is published on all interfaces with a passwordless `default` user that has access management enabled | Open |
| M-1 | Medium   | No validation or size limits on `domain`, `deploy_url`, `repo`, `advisory_id`, or path and query IDs | **Fixed** |
| M-2 | Medium   | SSRF hardening gaps in `verify/runtime.py`: scheme, credentials, malformed port crash, implicit redirects | **Fixed** |
| M-3 | Medium   | Prerelease builds of a fix version are reported as not affected (false negative) | Open (xfail test) |
| M-4 | Medium   | DNS-rebinding TOCTOU in `discovery/net.safe_fetch`; incomplete blocklist | Open |
| M-5 | Medium   | Unbounded resource use: target creation, polling fan-out, no rate limiting | Open |
| L-1 | Low      | Information disclosure through the event feed and `/api/stats` | Open |
| L-2 | Low      | Callers can forge the run `trigger` (audit-trail integrity) | Open |
| L-3 | Low      | Demo replay writes a cwd-relative `config/demo.yaml`, with no lock | Open |
| L-4 | Low      | Repo-local `.npmrc` is honoured during lockfile generation (blind SSRF) | Open (mitigated by H-2 fix) |
| L-5 | Low      | Cache paths depend on cwd; OSV `advisory_id` is used as a filename | Open |
| L-6 | Low      | Bare `except:` clauses; LLM prompt built from untrusted advisory text | Open |

What is already done well:
- Every ClickHouse query that takes user input is parameterized. The only f-string SQL is `store.get_record_counts`, which uses a hard-coded table list.
- `yaml.safe_load` is used throughout.
- All subprocesses take argv lists, never `shell=True`.
- `npm` runs with `--ignore-scripts`, and Semgrep runs with `--metrics=off`.
- `safe_fetch` re-validates every redirect hop and caps response bodies.
- FastAPI rejects non-JSON bodies, which blocks simple-form CSRF. A test now covers this.
- There are no hardcoded secrets, and `.env` is gitignored.

---

## H-1: Target ID spoofing and hijacking (Fixed)

**Where:** `app/main.py` `create_target`

**Attack:** `POST /api/targets` accepted any `target_id` that matched `^t_[a-z0-9_]{1,40}$` and overwrote whatever was registered under it.
- **Spoofing:** anyone could bind the pre-authorized `t_juiceshop` with any `kind`, `repo`, or `deploy_url`. Verification re-checks the kind and the pinned repo, so the worst effects were blocked. But the stored target was still replaced, and its future scans, watcher polls, and event feed then ran on attacker-controlled parameters.
- **Hijacking:** reusing any existing target ID silently replaced the victim's target in memory and in ClickHouse. `ReplacingMergeTree` keeps the latest row, so the change persisted. The victim's next run or poll then scanned the attacker's repo or domain.

**Fix:**
- A pre-authorized ID can be bound only when the request matches its configured scope: the kind is allowed, the repo equals the pinned repo, and the `deploy_url` host is in `allowed_hosts`. Anything else returns `403`. Re-binding with the exact configured scope stays idempotent, so `scripts/demo_check.py` keeps working.
- Any other caller-supplied ID that already exists, in memory or in ClickHouse, returns `409`.

**Tests:**
- `tests/test_api.py::test_spoofing_pinned_target_is_forbidden`
- `tests/test_api.py::test_existing_unpinned_target_cannot_be_hijacked`
- `tests/test_api.py::test_hijack_check_also_consults_clickhouse`
- `tests/test_api.py::test_rebinding_pinned_target_is_idempotent`

## H-2: Server filesystem access through `repo` (Fixed)

**Where:** `app/main.py`, `app/discovery/repo.py`, `app/verify/__init__.py`, `app/config.py`

**Attack:** Discovery is not gated by authorization, so it runs for every target. An unauthenticated caller could create a `connected_repo` target with `repo="/"`, `"/Users/<x>/project"`, or `"../../.."`. Then:
- `discover_repo` read `package.json` and lockfiles from any directory. Package names and versions came back through `/api/runs/{id}/report`, and the existence of paths leaked through `/api/events`.
- With no lockfile present, `_resolve_lockfile` ran `shutil.copytree` on the whole target directory (`repo="/"` means copying the disk) and then ran `npm install` inside it. That is a disk and CPU DoS, and it pairs with L-4.
- Discovery resolved relative paths against the **process cwd**, while the authorization gate resolved them against `PROJECT_ROOT`. When the server starts outside the repo root, the path that was checked is not the path that gets scanned.

**Fix:**
- New `config.ALLOWED_REPO_ROOTS`, set through the `ALLOWED_REPO_ROOTS` env var as an `os.pathsep`-separated list that defaults to `demo/`.
- New `config.resolve_repo_path`, which always anchors at `PROJECT_ROOT` and follows symlinks.
- New `config.is_repo_path_allowed`.
- The API rejects out-of-root repos with `400` and stores the normalized absolute path.
- `discover_repo` independently refuses out-of-root paths before any file access.
- `verify()` hands presence and Semgrep the same resolved path that the gate checked.

**Tests:**
- `tests/test_discovery.py::test_repo_outside_allowed_roots_is_never_read`: confirms no `open`, `copytree`, or `npm` call happens.
- `tests/test_discovery.py::test_symlink_escaping_allowed_root_is_refused`
- `tests/test_discovery.py::test_nul_byte_repo_path_is_refused`
- `tests/test_discovery.py::test_relative_repo_resolves_against_project_root_not_cwd`
- `tests/test_api.py::test_repo_outside_allowed_roots_rejected`
- `tests/test_verify.py::test_verify_scans_repo_resolved_from_project_root`

**Operator note:** to scan repos outside `demo/`, set `ALLOWED_REPO_ROOTS`, for example `ALLOWED_REPO_ROOTS=demo:/srv/repos`.

## H-3: No authentication; IDOR on findings (Open)

**Where:** every route in `app/main.py`

Anyone who can reach the port can create targets, start runs, read any target's events (`/api/events?target_id=`), and read any report. Run IDs look like `r_<YYYYmmdd_HHMMSS>_<4 hex>`. That is only 65,536 candidates per second of start time, so a run started near a known time can be found by brute force. Target IDs carry 32 bits of randomness and are returned to whoever created them.

**Recommendation:**
- Require a bearer token, such as an `API_TOKEN` env var checked by a FastAPI dependency.
- Record an owner on each target and check it on every `target_id` and `run_id` lookup.
- Generate run IDs with `uuid4().hex`.
- Bind uvicorn to `127.0.0.1` for demos.

## H-4: ClickHouse exposed with no password (Open)

**Where:** `docker-compose.yml`, `app/config.py`

`docker-compose.yml` publishes `8123` and `9000` on `0.0.0.0` and turns on `CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1` for the passwordless `default` user. `config.py` defaults `CLICKHOUSE_USER=default` and `CLICKHOUSE_PASSWORD=""`. Anyone on the LAN gets full admin access to the database and can read, alter, or drop findings, or create users.

**Recommendation:**
- Publish the ports as `127.0.0.1:8123:8123` and `127.0.0.1:9000:9000`.
- Set `CLICKHOUSE_PASSWORD`.
- Give the app its own least-privilege user (INSERT and SELECT on `cyberdefense.*`), separate from the admin account used by `scripts/apply_schema.py`.
- Refuse to start when the password is empty and `DEMO_MODE` is off.

## M-1: Missing input validation and size limits (Fixed)

**Where:** `app/main.py` request models and route parameters

**Problems:**
- `domain`, `repo`, `deploy_url`, `StartRunRequest.target_id`, `ReplayRequest.advisory_id`, the `run_id` and `target_id` path parameters, and `since` had no length or format limits.
- `domain` was interpolated straight into `https://{domain}/`, so values like `127.0.0.1:8123/?query=...`, `user@host`, or `evil.com/path` changed the request URL. `safe_fetch`'s IP check limited the damage, but the URL was still attacker-shaped.

**Fix:**
- `domain` must be an RFC 1123 hostname of at most 253 characters, with no scheme, port, path, or userinfo.
- `deploy_url` must be `http` or `https`, have a hostname, carry no credentials, and have a valid port, in at most 2,048 characters.
- `repo` is at most 1,024 characters and may not contain NUL bytes.
- Target IDs must match `^t_[a-z0-9_]{1,40}$` in the body, path, and query.
- Run IDs must match `^r_[A-Za-z0-9_]{1,60}$`.
- `advisory_id` must match `^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$`.
- `since` is at most 64 characters.

**Tests:**
- `tests/test_api.py::test_create_target_input_validation` (18 cases)
- `tests/test_api.py::test_read_endpoints_reject_malformed_ids`
- `tests/test_api.py::test_start_run_validation`
- `tests/test_api.py::test_replay_advisory_id_validation`

## M-2: SSRF hardening in `verify/runtime.py` (Fixed)

**Where:** `app/verify/runtime.py` `check_runtime`

Comparing against the host allowlist was correct for the userinfo trick: `http://localhost:3004@evil.com` parses to hostname `evil.com` and was refused. But:
- The scheme was never checked. `file://`, `gopher://`, and other schemes on an allowed host:port reached `httpx`, which happens to reject them today. That was defense by accident.
- Credentials in the URL were forwarded to the allowed host.
- `urlparse(...).port` raises `ValueError` on a malformed port such as `:99999`. The exception was not caught, so it propagated out of `verify()` and failed the whole run. One malformed target could deny verification.
- Redirect behaviour relied on `httpx`'s default.

**Fix:**
- New `deploy_url_refusal()` enforces `http`/`https`, a hostname, no credentials, and a parseable port, then applies the allowlist.
- `check_runtime` uses it, and the API reuses it for pinned targets.
- `follow_redirects=False` is now explicit.

**Tests:**
- `tests/test_verify.py::test_runtime_refuses_ssrf_variants_without_connecting` (7 variants)
- `tests/test_verify.py::test_runtime_does_not_follow_redirects`

**Residual risk:**
- An allowlist entry without a port (for example `localhost`) allows **every** port on that host. Keep entries in `host:port` form.
- Allowed hostnames are resolved at request time and not pinned, so rebinding can affect DNS-based entries. Prefer IP-literal entries.

## M-3: Prerelease false negative in range matching (Open)

**Where:** `app/intel/match.py` `_normalize_version`

`_normalize_version` drops prerelease suffixes. So `4.17.21-beta.1` is compared as `4.17.21` and treated as fixed, even though in semver it sorts **before** `4.17.21` and is still vulnerable. This is a missed-vulnerability bug.

**Recommendation:** parse with `semver.Version.parse` directly, keeping the prerelease, and normalize only missing minor or patch parts.

**Test:** `tests/test_intel.py::test_prerelease_of_fixed_version_is_still_affected` is marked `xfail(strict=True)`. Once this is fixed, that test will start passing, which makes the strict xfail fail the suite as a reminder to remove the marker.

## M-4: DNS-rebinding TOCTOU in public discovery (Open)

**Where:** `app/discovery/net.py`

`_check_url` resolves the hostname and checks every address, and then `httpx` resolves it **again** when it connects. An attacker-controlled domain with a very short TTL can pass the check with a public IP and then connect to `127.0.0.1`, `169.254.169.254`, and so on.

The blocklist also misses `198.18.0.0/15`, `192.0.0.0/24`, NAT64 `64:ff9b::/96`, and 6to4 `2002::/16`.

**Recommendation:**
- Connect to the IP that was validated, sending the original `Host` header and SNI. For example, use a custom `httpx` transport or pass a pinned-IP `local_address` resolver.
- Replace the hand-written list with `not ip.is_global`.

## M-5: Unbounded resource consumption (Open)

**Problems:**
- `orchestrator._targets` grows without limit, and the watcher polls every non-public target every `POLL_INTERVAL_SECONDS`. Creating many targets therefore amplifies outbound OSV traffic and ClickHouse writes.
- Each target allows one active run plus one queued run, but nothing caps the total across targets.
- `_resolve_lockfile` copies the whole repo, excluding only `node_modules`.

**Recommendation:**
- Add per-client rate limiting, for example with `slowapi`.
- Cap total targets and concurrent runs, using a global semaphore around `run_pipeline`.
- Cap the size of the `copytree` and skip `.git`.

## L-1: Information disclosure (Open)

**Problems:**
- Events contain absolute server paths (`Scanning repo at /abs/path`), raw exception text, up to 200 characters of `npm` and Semgrep stderr, and upstream `Server` headers. Combined with H-3, anyone can read them.
- `/api/stats` exposes table row counts and `demo_mode`.

**Recommendation:** use generic event messages, log the details server-side, and gate `/api/stats` behind auth.

## L-2: Caller-controlled `trigger` (Open)

`StartRunRequest.trigger` accepts `advisory`, `stack_change`, and `schedule`, so manual runs can be logged as if the system triggered them.

**Recommendation:** accept only `manual` from the API.

## L-3: Demo replay integrity (Open)

`watcher.release_holdback` reads and writes `Path("config/demo.yaml")` relative to the cwd, but `config.load_demo_config` reads `PROJECT_ROOT/config/demo.yaml`. When the cwd differs, the endpoint rewrites the wrong file or fails. There is no file lock, and `yaml.dump` drops comments.

The endpoint is reachable only when `DEMO_MODE` is on, but without authentication while it is.

**Recommendation:** anchor the path at `PROJECT_ROOT`, write atomically (temp file plus `os.replace`) under a lock, and require auth.

## L-4: Repo-local `.npmrc` during lockfile resolution (Open, mitigated)

`npm install --package-lock-only --ignore-scripts` still honours a `.npmrc` inside the scanned repo, including `registry=` and `@scope:registry=`. That makes the server send requests to whatever host the repo names, which is blind SSRF. The H-2 fix limits this to repos under the operator-controlled roots.

**Recommendation:** pass `--registry=https://registry.npmjs.org/`, delete `.npmrc` from the temp copy before running `npm`, and run `npm` in a network-restricted sandbox.

## L-5: Cache path handling (Open)

**Problems:**
- `data/raw` (in `net.py`) and `data/cache/osv` (in `osv.py`) are relative to the cwd.
- `osv.fetch_advisory` builds `CACHE_DIR / f"{advisory_id}.json"` from IDs returned by OSV. Upstream is trusted and reached over TLS, but a malformed ID such as `../x` would escape the directory.
- Cached pages never expire, and a cache hit returns no headers.

**Recommendation:** anchor these paths at `PROJECT_ROOT`, validate `advisory_id` against `^[A-Za-z0-9._:-]+$` before using it as a filename, and add a TTL.

## L-6: Code hygiene (Open)

**Problems:**
- Bare `except:` clauses in `intel/severity.py`, `intel/osv.py`, `intel/match.py`, and `verify/presence.py` also swallow `KeyboardInterrupt` and `SystemExit`.
- `intel/explain.py` puts untrusted advisory summaries into the LLM prompt. The output guard checks only versions and CVE or GHSA IDs. The function is not wired into the pipeline today.

**Recommendation:** use `except Exception`, and treat LLM output as untrusted display text by escaping it in the UI.

---

## Test coverage added

| File | Tests | Focus |
|------|-------|-------|
| `tests/test_intel.py` | 65 + 1 xfail | CVSS and GHSA severity edge cases, OSV parsing, semver range boundaries, matching, risk score, LLM guard, holdback watcher |
| `tests/test_discovery.py` | 57 | v1, v2, and v3 lockfiles, direct vs. transitive deps, aliases, repo confinement (traversal, symlink, NUL), public-target gating, SSRF IP and redirect guard |
| `tests/test_api.py` | 61 | All routes over `httpx.AsyncClient`/ASGI with ClickHouse mocked: spoofing, hijack, validation, CSRF content type, report assembly, parameterized SQL |
| `tests/test_verify.py` | 42 to 51 | Runtime SSRF variants, redirect pinning, gate and scan path consistency |

Total: **234 passed, 1 xfailed** (the 1 xfail is M-3). The baseline was 42.

Run the suite with the project dependencies installed:

```sh
python3 -m venv .venv
.venv/bin/pip install fastapi pydantic httpx clickhouse-connect semver cvss pyyaml pytest anyio
.venv/bin/python -m pytest tests/ -v
```

With a bare `python3` that lacks `cvss`, `semver`, or `clickhouse-connect`, `test_intel.py` and `test_api.py` are skipped with a clear reason instead of failing at import.
