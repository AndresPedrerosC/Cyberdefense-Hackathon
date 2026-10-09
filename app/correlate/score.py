"""Contextual severity: impact class adjusted by how reachable the flaw is in this app.

Deterministic on purpose. Every adjustment appends a reason, so the severity shown in the UI is
auditable: an analyst can disagree with a specific step instead of with a black box. The
advisory's own CVSS rating is kept alongside, never hidden.
"""

from app.correlate.reach import Reach
from app.intel.impact import IMPACT_BASE, IMPACT_TITLE

LEVELS = ["low", "medium", "high", "critical"]
# Impacts that get worse when the org visibly handles payments or credentials.
STAKES_IMPACTS = {"auth-bypass", "crypto-weakness", "data-exposure", "injection", "xss"}


def score_dependency(impact: str, impact_why: str, reach: Reach, cvss: str, match_type: str,
                     stakes: list[str]) -> tuple[str, list[str]]:
    base = IMPACT_BASE.get(impact, "low")
    reasons: list[str] = []
    if impact == "info" and cvss in LEVELS:
        base = cvss
        reasons.append(f"Impact unclear from the advisory, starting from its {cvss} rating")
    else:
        reasons.append(f"{IMPACT_TITLE.get(impact, impact)} ({impact_why}) starts at {base}")
    lvl = LEVELS.index(base)

    if reach.tier == "exposed":
        entry = reach.route_label or "a route"
        if reach.auth_required:
            lvl -= 1
            reasons.append(f"{entry} requires authentication (-1)")
        else:
            live = ", and the live app answers it" if reach.observed_live else ""
            every = " on every request" if reach.global_middleware else ""
            reasons.append(f"Reachable without authentication from {entry}{every}{live}")
        if reach.symbol:
            reasons.append(f"Vulnerable API {reach.symbol} is called at {reach.symbol_at}")
        elif not reach.direct_call:
            lvl -= 1
            if reach.via:
                reasons.append(f"Reached through {reach.via[0]}; whether that package calls the "
                               "vulnerable code is not proven (-1)")
            else:
                reasons.append("The handler's code imports the package, but the vulnerable "
                               "function was not confirmed in use (-1)")
    elif reach.tier == "called":
        lvl -= 1
        reasons.append(f"Vulnerable API called at {reach.symbol_at}, but no HTTP route reaches "
                       "that code (-1)")
    elif reach.tier == "imported":
        lvl = min(lvl - 2, LEVELS.index("medium"))
        reasons.append("Imported by the app, but no HTTP route reaches the importing code "
                       "(-2, capped at medium)")
    else:
        lvl = 0
        reasons.append("Only in the lockfile: no source file imports it or anything that "
                       "depends on it (low)")

    if match_type == "possible":
        lvl -= 1
        reasons.append("Installed version could not be confirmed against the affected range (-1)")
    if stakes and impact in STAKES_IMPACTS and reach.tier in ("exposed", "called"):
        lvl += 1
        reasons.append(f"Raised because {stakes[0]} (+1)")
    lvl = max(0, min(lvl, len(LEVELS) - 1))
    return LEVELS[lvl], reasons


def score_exposure(severity: str, tier: str, where: str) -> tuple[str, list[str]]:
    """Secrets and misconfig: the scanner's severity, lowered when nothing serves the file."""
    base = severity if severity in LEVELS else "medium"
    lvl = LEVELS.index(base)
    reasons = [f"Scanner rated it {base}"]
    if tier == "exposed":
        reasons.append(f"Downloadable over HTTP at {where}")
    elif tier == "imported":
        lvl -= 1
        reasons.append(f"Loaded by app code ({where}) but not served; readable by anyone with "
                       "source or image access (-1)")
    else:
        lvl -= 1
        reasons.append("Sits in the repository; no route serves it and no app code loads it (-1)")
    return LEVELS[max(0, lvl)], reasons
