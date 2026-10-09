"""Optional LLM-generated explanations for candidates."""

import re

from app.schema import Candidate, Advisory, Emit
from app.config import OPENAI_API_KEY, OPENAI_MODEL


def generate_explanation(candidate: Candidate, advisory: Advisory, emit: Emit) -> str | None:
    """Generate a 1-2 sentence explanation using OpenAI."""
    if not OPENAI_API_KEY:
        return None

    try:
        from openai import OpenAI
        client = OpenAI(api_key=OPENAI_API_KEY)

        prompt = f"""Explain in 1-2 sentences why this vulnerability affects this package.

Package: {candidate.stack_item_id.split('|')[2] if '|' in candidate.stack_item_id else 'unknown'}
Advisory: {advisory.advisory_id}
Summary: {advisory.summary or 'No summary available'}
Affected range: {candidate.affected_range}
Severity: {advisory.severity}

Be factual. Only reference information from the input."""

        response = client.chat.completions.create(
            model=OPENAI_MODEL or "gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=150,
            temperature=0.3,
        )

        explanation = response.choices[0].message.content.strip()

        # Post-check: reject if it contains version/CVE not in input
        if not _validate_explanation(explanation, candidate, advisory):
            emit("intel", "warn", f"Explanation rejected for {candidate.id}: hallucination detected", None)
            return None

        return explanation

    except Exception as e:
        emit("intel", "warn", f"Explanation generation failed: {e}", None)
        return None


def _validate_explanation(text: str, candidate: Candidate, advisory: Advisory) -> bool:
    """Validate explanation contains no hallucinated data."""
    # Extract version numbers from explanation
    versions_in_text = set(re.findall(r'\d+\.\d+\.\d+', text))

    # Build allowed versions
    allowed_versions = set()
    if candidate.fixed_version:
        allowed_versions.add(candidate.fixed_version)
    # Add versions from affected_range
    if candidate.affected_range:
        allowed_versions.update(re.findall(r'\d+\.\d+\.\d+', candidate.affected_range))

    # Check for disallowed versions
    for v in versions_in_text:
        if v not in allowed_versions:
            return False

    # Check CVE/GHSA IDs
    ids_in_text = set(re.findall(r'(CVE-\d{4}-\d+|GHSA-[a-z0-9-]+)', text, re.IGNORECASE))
    allowed_ids = {advisory.advisory_id.upper()} | {a.upper() for a in advisory.aliases}

    for id_ in ids_in_text:
        if id_.upper() not in allowed_ids:
            return False

    return True
