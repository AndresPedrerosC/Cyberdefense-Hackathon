"""Dependency presence verification."""

import json
from pathlib import Path

from app.schema import Candidate, StackItem, Emit


def check_presence(
    candidates: list[Candidate],
    stack_items: dict[str, StackItem],
    repo_path: str,
    emit: Emit,
) -> dict[str, bool]:
    """Check if candidate dependencies are actually present."""
    results = {}
    repo = Path(repo_path)

    # Load lockfile
    lockfile_path = repo / "package-lock.json"
    lockfile_packages = set()

    if lockfile_path.exists():
        try:
            lock = json.loads(lockfile_path.read_text())

            # v2/v3 format
            if "packages" in lock:
                for key in lock["packages"]:
                    if key.startswith("node_modules/"):
                        pkg_name = _extract_pkg_name(key)
                        if pkg_name:
                            lockfile_packages.add(pkg_name.lower())

            # v1 format
            elif "dependencies" in lock:
                _collect_v1_deps(lock["dependencies"], lockfile_packages)

        except Exception as e:
            emit("verification", "warn", f"Failed to parse lockfile: {e}", None)

    # Check each candidate
    for candidate in candidates:
        stack_item = stack_items.get(candidate.stack_item_id)
        if not stack_item or not stack_item.package:
            results[candidate.id] = None  # Can't verify
            continue

        pkg_name = stack_item.package.lower()
        version = stack_item.version

        # Check lockfile
        in_lockfile = pkg_name in lockfile_packages

        # Check node_modules if exists
        node_modules = repo / "node_modules" / stack_item.package
        in_node_modules = False

        if node_modules.exists():
            pkg_json = node_modules / "package.json"
            if pkg_json.exists():
                try:
                    pkg_data = json.loads(pkg_json.read_text())
                    installed_version = pkg_data.get("version")
                    if version and installed_version == version:
                        in_node_modules = True
                    elif not version:
                        in_node_modules = True  # Version unknown, just check presence
                except:
                    pass

        # Present if in lockfile OR node_modules
        results[candidate.id] = in_lockfile or in_node_modules

    return results


def _extract_pkg_name(key: str) -> str | None:
    """Extract package name from lockfile key."""
    if not key.startswith("node_modules/"):
        return None

    parts = key.split("node_modules/")
    last = parts[-1]

    if last.startswith("@"):
        return last  # Scoped package
    return last.split("/")[0]


def _collect_v1_deps(deps: dict, packages: set):
    """Recursively collect package names from v1 lockfile."""
    for name, info in deps.items():
        packages.add(name.lower())
        if "dependencies" in info:
            _collect_v1_deps(info["dependencies"], packages)
