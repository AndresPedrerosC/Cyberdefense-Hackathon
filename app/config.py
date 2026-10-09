import os
from pathlib import Path
import yaml

def get_env(key: str, default: str | None = None) -> str | None:
    return os.environ.get(key, default)

def get_env_int(key: str, default: int) -> int:
    val = os.environ.get(key)
    return int(val) if val else default

def get_env_bool(key: str, default: bool = False) -> bool:
    val = os.environ.get(key, "").lower()
    return val in ("1", "true", "yes") if val else default

_demo_config: dict | None = None

def load_demo_config() -> dict:
    global _demo_config
    if _demo_config is None:
        config_path = Path(__file__).parent.parent / "config" / "demo.yaml"
        if config_path.exists():
            with open(config_path) as f:
                _demo_config = yaml.safe_load(f) or {}
        else:
            _demo_config = {}
    return _demo_config

def is_target_authorized(target_id: str, kind: str) -> tuple[bool, str]:
    cfg = load_demo_config()
    targets = cfg.get("authorized_targets", {})
    if target_id not in targets:
        return False, f"target {target_id} not in authorized_targets"
    allowed_kinds = targets[target_id].get("kinds", [])
    if kind not in allowed_kinds:
        return False, f"kind {kind} not authorized for {target_id}"
    return True, f"{kind} in AUTHORIZED_TARGETS"

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def is_repo_authorized(target_id: str, repo: str | None) -> bool:
    """A configured repo path pins the target; any other path is refused."""
    entry = load_demo_config().get("authorized_targets", {}).get(target_id, {})
    configured = entry.get("repo")
    if not configured or not repo:
        return True
    expected = (PROJECT_ROOT / configured).resolve()
    actual = Path(repo)
    actual = (actual if actual.is_absolute() else PROJECT_ROOT / actual).resolve()
    return actual == expected

def get_allowed_hosts(target_id: str) -> list[str]:
    cfg = load_demo_config()
    return cfg.get("authorized_targets", {}).get(target_id, {}).get("allowed_hosts", [])

# Shortcuts
OPENAI_API_KEY = get_env("OPENAI_API_KEY")
OPENAI_MODEL = get_env("OPENAI_MODEL", "gpt-4o-mini")
CLICKHOUSE_HOST = get_env("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = get_env_int("CLICKHOUSE_PORT", 8123)
CLICKHOUSE_USER = get_env("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = get_env("CLICKHOUSE_PASSWORD", "")
CLICKHOUSE_DATABASE = get_env("CLICKHOUSE_DATABASE", "cyberdefense")
POLL_INTERVAL_SECONDS = get_env_int("POLL_INTERVAL_SECONDS", 300)
DEMO_MODE = get_env_bool("DEMO_MODE")
CACHE_ONLY = get_env_bool("CACHE_ONLY")
