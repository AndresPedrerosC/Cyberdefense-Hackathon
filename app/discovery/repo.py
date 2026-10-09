"""Repository-based discovery (connected repos)."""

import hashlib
import json
import subprocess
import tempfile
import shutil
from pathlib import Path

from app import config
from app.schema import Target, StackItem, Emit
from app.ids import stack_item_id

LOCK_CACHE_DIR = Path(__file__).resolve().parents[2] / "data" / "cache" / "lockfiles"


def discover_repo(target: Target, run_id: str, emit: Emit) -> list[StackItem]:
    """Discover stack from a connected repository."""
    if not config.is_repo_path_allowed(target.repo):
        emit("discovery", "error", "Repo path is outside ALLOWED_REPO_ROOTS; refusing to scan", None)
        return []
    repo_path = config.resolve_repo_path(target.repo)

    if not repo_path.exists():
        emit("discovery", "error", f"Repo path does not exist: {repo_path}", None)
        return []

    emit("discovery", "info", f"Scanning repo at {repo_path}", None)

    # Find manifests
    package_json = repo_path / "package.json"
    package_lock = repo_path / "package-lock.json"

    if not package_json.exists():
        emit("discovery", "warn", "No package.json found", None)
        return []

    # Load package.json for direct deps and declared ranges
    with open(package_json) as f:
        pkg = json.load(f)

    direct_deps = set()
    declared_ranges = {}
    for dep_type in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for name, version_range in pkg.get(dep_type, {}).items():
            direct_deps.add(name)
            declared_ranges[name] = version_range

    emit("discovery", "info", f"Found {len(direct_deps)} direct dependencies in package.json", None)

    # Check for lockfile
    if not package_lock.exists():
        emit("discovery", "warn", "No package-lock.json found, attempting to resolve", None)
        package_lock = _resolve_lockfile(repo_path, emit)
        if not package_lock:
            # Fallback: emit direct deps without versions
            return _emit_direct_deps_only(target, run_id, direct_deps, declared_ranges, emit)

    # Parse lockfile
    with open(package_lock) as f:
        lock = json.load(f)

    lockfile_version = lock.get("lockfileVersion", 1)
    emit("discovery", "info", f"Parsing lockfile version {lockfile_version}", None)

    items = []

    if lockfile_version >= 2 and "packages" in lock:
        # v2/v3 format
        items = _parse_v2_packages(target, run_id, lock["packages"], direct_deps, declared_ranges, package_lock)
    elif "dependencies" in lock:
        # v1 format
        items = _parse_v1_dependencies(target, run_id, lock["dependencies"], direct_deps, declared_ranges, package_lock)

    emit("discovery", "info", f"Parsed {len(items)} packages from lockfile", None)
    return items


def _resolve_lockfile(repo_path: Path, emit: Emit) -> Path | None:
    """Attempt to generate a lockfile using npm."""
    try:
        # Create temp copy to avoid modifying original
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_repo = Path(tmpdir) / "repo"
            shutil.copytree(repo_path, tmp_repo, ignore=shutil.ignore_patterns("node_modules"))

            emit("discovery", "info", "Running npm install --package-lock-only", None)

            result = subprocess.run(
                ["npm", "install", "--package-lock-only", "--ignore-scripts"],
                cwd=tmp_repo,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode == 0:
                generated_lock = tmp_repo / "package-lock.json"
                if generated_lock.exists():
                    cache_dir = LOCK_CACHE_DIR / hashlib.sha1(str(repo_path).encode()).hexdigest()[:12]
                    cache_dir.mkdir(parents=True, exist_ok=True)
                    dest = cache_dir / "package-lock.json"
                    shutil.copy(generated_lock, dest)
                    emit("discovery", "info", "Generated lockfile via npm", None)
                    return dest
            else:
                emit("discovery", "warn", f"npm failed: {result.stderr[:200]}", None)
    except subprocess.TimeoutExpired:
        emit("discovery", "warn", "npm install timed out", None)
    except FileNotFoundError:
        emit("discovery", "warn", "npm not available", None)
    except Exception as e:
        emit("discovery", "warn", f"Lockfile resolution failed: {e}", None)

    return None


def _emit_direct_deps_only(
    target: Target, run_id: str, direct_deps: set, declared_ranges: dict, emit: Emit
) -> list[StackItem]:
    """Fallback: emit direct deps without resolved versions."""
    items = []
    for name in direct_deps:
        sid = stack_item_id(target.target_id, "npm", name, "")
        items.append(StackItem(
            id=sid,
            run_id=run_id,
            target_id=target.target_id,
            ecosystem="npm",
            package=name,
            name=name,
            version=None,
            declared_range=declared_ranges.get(name),
            direct=True,
            confidence="medium",
            status="confirmed",
            source_url=None,
            evidence=f"From package.json (no lockfile): {declared_ranges.get(name)}",
        ))
    emit("discovery", "warn", f"Emitting {len(items)} deps without resolved versions", None)
    return items


def _parse_v2_packages(
    target: Target, run_id: str, packages: dict, direct_deps: set, declared_ranges: dict, lockfile_path: Path
) -> list[StackItem]:
    """Parse lockfile v2/v3 packages map."""
    items = []
    seen_ids = set()

    for key, info in packages.items():
        if key == "":
            continue  # Root package

        # Extract package name from key (e.g., "node_modules/@scope/name" or "node_modules/name")
        name = _extract_package_name(key)
        if not name:
            continue

        version = info.get("version")
        if not version:
            continue

        is_direct = name in direct_deps and key == f"node_modules/{name}"

        sid = stack_item_id(target.target_id, "npm", name, version)
        if sid in seen_ids:
            continue
        seen_ids.add(sid)
        items.append(StackItem(
            id=sid,
            run_id=run_id,
            target_id=target.target_id,
            ecosystem="npm",
            package=name,
            name=name,
            version=version,
            declared_range=declared_ranges.get(name) if is_direct else None,
            direct=is_direct,
            confidence="high",
            status="confirmed",
            source_url=f"file://{lockfile_path}",
            evidence=json.dumps({"key": key, "version": version}),
        ))

    return items


def _parse_v1_dependencies(
    target: Target, run_id: str, dependencies: dict, direct_deps: set, declared_ranges: dict, lockfile_path: Path
) -> list[StackItem]:
    """Parse lockfile v1 dependencies recursively."""
    items = []
    seen_ids = set()

    def walk(deps: dict, path: str = ""):
        for name, info in deps.items():
            version = info.get("version")
            if not version:
                continue

            is_direct = name in direct_deps and path == ""

            sid = stack_item_id(target.target_id, "npm", name, version)
            if sid not in seen_ids:
                seen_ids.add(sid)
                items.append(StackItem(
                    id=sid,
                    run_id=run_id,
                    target_id=target.target_id,
                    ecosystem="npm",
                    package=name,
                    name=name,
                    version=version,
                    declared_range=declared_ranges.get(name) if is_direct else None,
                    direct=is_direct,
                    confidence="high",
                    status="confirmed",
                    source_url=f"file://{lockfile_path}",
                    evidence=json.dumps({"name": name, "version": version}),
                ))

            # Recurse into nested dependencies
            if "dependencies" in info:
                walk(info["dependencies"], f"{path}/{name}")

    walk(dependencies)
    return items


def _extract_package_name(key: str) -> str | None:
    """Extract package name from lockfile key."""
    # Handle "node_modules/@scope/name" or "node_modules/name"
    # Also nested: "node_modules/a/node_modules/b"
    if not key.startswith("node_modules/"):
        return None

    parts = key.split("node_modules/")
    last_part = parts[-1]

    # Handle scoped packages
    if last_part.startswith("@"):
        # @scope/name
        return last_part
    else:
        # Regular package, take first segment
        return last_part.split("/")[0] if "/" in last_part else last_part
