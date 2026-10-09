from app.discovery.repo import discover_repo
from app.discovery.public import discover_public

from app.schema import Target, StackItem, Emit


def discover(target: Target, run_id: str, emit: Emit) -> list[StackItem]:
    """Main discovery entry point."""
    emit("discovery", "info", f"Starting discovery for {target.name}", None)

    if target.kind in ("connected_repo", "owned_deployment") and target.repo:
        items = discover_repo(target, run_id, emit)
    elif target.kind == "public" and target.domain:
        items = discover_public(target, run_id, emit)
    else:
        emit("discovery", "warn", f"No valid discovery path for target kind={target.kind}", None)
        items = []

    direct_count = sum(1 for i in items if i.direct)
    emit("discovery", "info", f"Discovery complete: {len(items)} items ({direct_count} direct)", None)
    return items
