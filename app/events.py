"""Event emission utilities."""

from datetime import datetime
from app.schema import Event, EventStage, EventLevel
from app import store


def emit_event(
    stage: EventStage,
    level: EventLevel,
    message: str,
    target_id: str,
    run_id: str | None = None,
    ref_id: str | None = None,
) -> Event:
    event = Event(
        target_id=target_id,
        run_id=run_id,
        stage=stage,
        level=level,
        message=message,
        ref_id=ref_id,
        ts=datetime.utcnow(),
    )
    store.insert_event(event)
    return event


def make_emit(target_id: str, run_id: str | None = None):
    """Create an emit callback for a pillar."""
    def emit(stage: str, level: str, message: str, ref_id: str | None = None) -> None:
        emit_event(stage, level, message, target_id, run_id, ref_id)
    return emit
