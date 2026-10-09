"""OpenAI-compatible chat client for the recon agent (local Ollama by default)."""

import httpx

from app.config import LLM_API_KEY, LLM_BASE_URL, LLM_ENABLED, LLM_MODEL


def get_client():
    from openai import OpenAI

    return OpenAI(base_url=LLM_BASE_URL, api_key=LLM_API_KEY or "unused", timeout=90.0,
                  max_retries=0)


def is_available() -> tuple[bool, str]:
    """Cheap reachability check so a stopped Ollama degrades to recon-only, not a failed run."""
    if not LLM_ENABLED:
        return False, "LLM_ENABLED is off"
    try:
        r = httpx.get(LLM_BASE_URL.rstrip("/") + "/models", timeout=3.0,
                      headers={"Authorization": f"Bearer {LLM_API_KEY or 'unused'}"})
        r.raise_for_status()
        ids = {m.get("id") for m in r.json().get("data", [])}
        if ids and LLM_MODEL not in ids:
            return False, f"model {LLM_MODEL} is not loaded at {LLM_BASE_URL}"
        return True, LLM_MODEL
    except Exception as e:
        return False, f"{LLM_BASE_URL} unreachable ({type(e).__name__})"
