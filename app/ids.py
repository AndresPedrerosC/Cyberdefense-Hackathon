import hashlib

def _hash_id(*parts: str) -> str:
    joined = "|".join(parts)
    return hashlib.sha1(joined.encode()).hexdigest()[:16]

def stack_item_id(target_id: str, ecosystem: str, package_or_name: str, version: str | None) -> str:
    return _hash_id(target_id, ecosystem, package_or_name.lower(), version or "")

def candidate_id(stack_item_id: str, advisory_id: str) -> str:
    return _hash_id(stack_item_id, advisory_id)

def verification_id(candidate_id: str, run_id: str) -> str:
    return _hash_id(candidate_id, run_id)
