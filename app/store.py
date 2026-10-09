"""ClickHouse storage layer."""

import json
from datetime import datetime
from typing import Any

import clickhouse_connect
from clickhouse_connect.driver.client import Client

from app.config import (
    CLICKHOUSE_HOST,
    CLICKHOUSE_PORT,
    CLICKHOUSE_USER,
    CLICKHOUSE_PASSWORD,
    CLICKHOUSE_DATABASE,
)
from app.schema import (
    Target, Run, StackItem, Advisory, Candidate, Verification, Event
)

_client: Client | None = None
_last_query_latency_ms: float = 0.0


def get_client() -> Client:
    global _client
    if _client is None:
        _client = clickhouse_connect.get_client(
            host=CLICKHOUSE_HOST,
            port=CLICKHOUSE_PORT,
            username=CLICKHOUSE_USER,
            password=CLICKHOUSE_PASSWORD or "",
            database=CLICKHOUSE_DATABASE,
            # Shared across pipeline threads; ClickHouse rejects concurrent queries per session.
            autogenerate_session_id=False,
        )
    return _client


def get_last_query_latency() -> float:
    return _last_query_latency_ms


def _serialize_json(obj: Any) -> str:
    if obj is None:
        return ""
    if isinstance(obj, list):
        return json.dumps([item.model_dump() if hasattr(item, "model_dump") else item for item in obj])
    return json.dumps(obj)


def _ts(dt: datetime | None) -> datetime:
    return dt or datetime.utcnow()


# Insert functions (batch)
def insert_target(target: Target) -> None:
    client = get_client()
    client.insert(
        "targets",
        [[
            target.target_id,
            target.kind,
            target.name,
            target.domain or "",
            target.repo or "",
            target.deploy_url or "",
            _ts(target.created_ts),
        ]],
        column_names=["target_id", "kind", "name", "domain", "repo", "deploy_url", "created_ts"],
    )


def insert_run(run: Run) -> None:
    client = get_client()
    client.insert(
        "runs",
        [[
            run.run_id,
            run.target_id,
            run.trigger,
            run.state,
            1 if run.verification_authorized else 0,
            run.authorization_reason or "",
            run.inventory_hash or "",
            _ts(run.started_ts),
            run.finished_ts,
            run.error,
            datetime.utcnow(),
        ]],
        column_names=[
            "run_id", "target_id", "trigger", "state", "verification_authorized",
            "authorization_reason", "inventory_hash", "started_ts", "finished_ts", "error", "ts"
        ],
    )


def insert_stack_items(items: list[StackItem]) -> None:
    if not items:
        return
    client = get_client()
    rows = [
        [
            item.id,
            item.run_id,
            item.target_id,
            _ts(item.ts),
            item.ecosystem,
            item.package or "",
            item.name or "",
            item.version,
            item.declared_range,
            1 if item.direct else 0,
            item.confidence,
            item.status,
            item.source_url or "",
            item.evidence or "",
        ]
        for item in items
    ]
    client.insert(
        "stack_items",
        rows,
        column_names=[
            "id", "run_id", "target_id", "ts", "ecosystem", "package", "name",
            "version", "declared_range", "direct", "confidence", "status", "source_url", "evidence"
        ],
    )


def insert_advisories(advisories: list[Advisory]) -> None:
    if not advisories:
        return
    client = get_client()
    rows = [
        [
            adv.advisory_id,
            json.dumps(adv.aliases),
            adv.ecosystem,
            adv.package,
            _serialize_json(adv.ranges),
            json.dumps(adv.versions),
            adv.severity,
            adv.cvss_vector or "",
            adv.summary or "",
            _ts(adv.published),
            _ts(adv.modified),
            adv.withdrawn,
            adv.source,
            adv.source_url or "",
            _ts(adv.first_seen),
            1 if adv.replayed else 0,
        ]
        for adv in advisories
    ]
    client.insert(
        "advisories",
        rows,
        column_names=[
            "advisory_id", "aliases", "ecosystem", "package", "ranges", "versions",
            "severity", "cvss_vector", "summary", "published", "modified", "withdrawn",
            "source", "source_url", "first_seen", "replayed"
        ],
    )


def insert_candidates(candidates: list[Candidate]) -> None:
    if not candidates:
        return
    client = get_client()
    rows = [
        [
            c.id,
            c.run_id,
            c.target_id,
            _ts(c.ts),
            c.stack_item_id,
            c.advisory_id,
            c.advisory_url or "",
            c.affected_range or "",
            c.fixed_version,
            c.match_type,
            c.reason or "",
            c.explanation,
            c.severity_hint,
            c.risk_score,
        ]
        for c in candidates
    ]
    client.insert(
        "candidates",
        rows,
        column_names=[
            "id", "run_id", "target_id", "ts", "stack_item_id", "advisory_id",
            "advisory_url", "affected_range", "fixed_version", "match_type",
            "reason", "explanation", "severity_hint", "risk_score"
        ],
    )


def insert_verifications(verifications: list[Verification]) -> None:
    if not verifications:
        return
    client = get_client()
    rows = [
        [
            v.id,
            v.run_id,
            v.target_id,
            _ts(v.ts),
            v.candidate_id,
            v.status,
            _serialize_json(v.evidence),
            json.dumps(v.checks_performed),
            v.suggested_fix or "",
            v.target or "",
        ]
        for v in verifications
    ]
    client.insert(
        "verifications",
        rows,
        column_names=[
            "id", "run_id", "target_id", "ts", "candidate_id", "status",
            "evidence", "checks_performed", "suggested_fix", "target"
        ],
    )


def insert_event(event: Event) -> None:
    client = get_client()
    client.insert(
        "events",
        [[
            event.event_id,
            event.run_id,
            event.target_id,
            _ts(event.ts),
            event.stage,
            event.level,
            event.message,
            event.ref_id,
        ]],
        column_names=[
            "event_id", "run_id", "target_id", "ts", "stage", "level", "message", "ref_id"
        ],
    )


# Query functions
def _timed_query(query: str, params: dict | None = None):
    global _last_query_latency_ms
    import time
    client = get_client()
    start = time.perf_counter()
    result = client.query(query, parameters=params)
    _last_query_latency_ms = (time.perf_counter() - start) * 1000
    return result


def get_events(target_id: str, since: datetime | None = None, limit: int = 200) -> list[dict]:
    since_ts = since or datetime(1970, 1, 1)
    result = _timed_query(
        """
        SELECT ts, stage, level, message, ref_id, run_id, event_id
        FROM events
        WHERE target_id = {target_id:String} AND ts > {since:DateTime64(3)}
        ORDER BY ts DESC
        LIMIT {limit:UInt32}
        """,
        {"target_id": target_id, "since": since_ts, "limit": limit},
    )
    return [
        {"ts": row[0], "stage": row[1], "level": row[2], "message": row[3], "ref_id": row[4], "run_id": row[5], "event_id": str(row[6])}
        for row in result.result_rows
    ]


def get_new_candidates(current_run_id: str, previous_run_id: str) -> list[str]:
    result = _timed_query(
        """
        SELECT id, advisory_id FROM candidates WHERE run_id = {cur:String}
        AND id NOT IN (SELECT id FROM candidates WHERE run_id = {prev:String})
        """,
        {"cur": current_run_id, "prev": previous_run_id},
    )
    return [row[0] for row in result.result_rows]


def get_recurring_findings(target_id: str, min_runs: int = 3) -> list[dict]:
    result = _timed_query(
        """
        SELECT c.id, any(c.advisory_id), uniqExact(c.run_id) AS runs_seen
        FROM candidates c WHERE c.target_id = {t:String}
        GROUP BY c.id HAVING runs_seen >= {min:UInt32}
        """,
        {"t": target_id, "min": min_runs},
    )
    return [{"id": row[0], "advisory_id": row[1], "runs_seen": row[2]} for row in result.result_rows]


def get_verification_changes(current_run_id: str, previous_run_id: str) -> list[dict]:
    result = _timed_query(
        """
        SELECT a.candidate_id, b.status AS before, a.status AS after
        FROM verifications a JOIN verifications b USING (candidate_id)
        WHERE a.run_id = {cur:String} AND b.run_id = {prev:String} AND a.status != b.status
        """,
        {"cur": current_run_id, "prev": previous_run_id},
    )
    return [{"candidate_id": row[0], "before": row[1], "after": row[2]} for row in result.result_rows]


def get_corpus_stats() -> dict:
    result = _timed_query(
        "SELECT severity, count() FROM advisories WHERE ecosystem = 'npm' GROUP BY severity"
    )
    by_severity = {row[0]: row[1] for row in result.result_rows}

    total_result = _timed_query("SELECT count() FROM advisories")
    total = total_result.result_rows[0][0] if total_result.result_rows else 0

    return {"total": total, "by_severity": by_severity}


def get_run(run_id: str) -> dict | None:
    result = _timed_query(
        """
        SELECT run_id, target_id, trigger, state, verification_authorized,
               authorization_reason, inventory_hash, started_ts, finished_ts, error
        FROM runs WHERE run_id = {run_id:String}
        ORDER BY ts DESC LIMIT 1
        """,
        {"run_id": run_id},
    )
    if not result.result_rows:
        return None
    row = result.result_rows[0]
    return {
        "run_id": row[0], "target_id": row[1], "trigger": row[2], "state": row[3],
        "verification_authorized": bool(row[4]), "authorization_reason": row[5],
        "inventory_hash": row[6], "started_ts": row[7], "finished_ts": row[8], "error": row[9],
    }


def get_latest_complete_run(target_id: str) -> dict | None:
    result = _timed_query(
        """
        SELECT run_id, target_id, trigger, state, verification_authorized,
               authorization_reason, inventory_hash, started_ts, finished_ts, error
        FROM runs WHERE target_id = {target_id:String} AND state = 'complete'
        ORDER BY finished_ts DESC LIMIT 1
        """,
        {"target_id": target_id},
    )
    if not result.result_rows:
        return None
    row = result.result_rows[0]
    return {
        "run_id": row[0], "target_id": row[1], "trigger": row[2], "state": row[3],
        "verification_authorized": bool(row[4]), "authorization_reason": row[5],
        "inventory_hash": row[6], "started_ts": row[7], "finished_ts": row[8], "error": row[9],
    }


def get_stack_items_for_run(run_id: str) -> list[dict]:
    result = _timed_query(
        """
        SELECT id, ecosystem, package, name, version, declared_range, direct,
               confidence, status, source_url
        FROM stack_items WHERE run_id = {run_id:String}
        """,
        {"run_id": run_id},
    )
    return [
        {
            "id": row[0], "ecosystem": row[1], "package": row[2], "name": row[3],
            "version": row[4], "declared_range": row[5], "direct": bool(row[6]),
            "confidence": row[7], "status": row[8], "source_url": row[9],
        }
        for row in result.result_rows
    ]


def get_known_advisory_ids(target_id: str) -> set[str]:
    result = _timed_query(
        "SELECT DISTINCT advisory_id FROM candidates WHERE target_id = {t:String}",
        {"t": target_id},
    )
    return {row[0] for row in result.result_rows}


def get_record_counts() -> dict:
    tables = ["targets", "runs", "stack_items", "advisories", "candidates", "verifications", "events"]
    counts = {}
    for table in tables:
        result = _timed_query(f"SELECT count() FROM {table}")
        counts[table] = result.result_rows[0][0] if result.result_rows else 0
    return counts
