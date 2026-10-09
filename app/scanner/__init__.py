"""Deep scanning pillar: vulnerability scanning, endpoint enumeration, threat correlation.

Results are kept in a per-run in-memory store so the API can serve them without a
ClickHouse schema migration. This is a deliberate hackathon-scope choice; persisting to
ClickHouse would mean new tables + store inserts, which is out of scope for these modules.
"""

from threading import Lock

_RESULTS: dict[str, dict] = {}
_LOCK = Lock()

_SECTIONS = ("vulnscan", "endpoints", "threats")


def store_scan_results(run_id: str, section: str, data: list | dict) -> None:
    if section not in _SECTIONS:
        raise ValueError(f"unknown scan section: {section!r}")
    with _LOCK:
        _RESULTS.setdefault(run_id, {})[section] = data


def get_scan_results(run_id: str, section: str) -> list | dict | None:
    with _LOCK:
        run = _RESULTS.get(run_id)
        return run.get(section) if run else None


def clear_scan_results(run_id: str) -> None:
    with _LOCK:
        _RESULTS.pop(run_id, None)
