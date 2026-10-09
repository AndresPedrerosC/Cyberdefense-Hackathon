__all__ = ["match", "poll"]


def __getattr__(name: str):
    # Lazy so app.intel.osv stays importable while match/watcher are absent.
    if name == "match":
        from app.intel.match import match_stack_items
        return match_stack_items
    if name == "poll":
        from app.intel.watcher import poll_advisories
        return poll_advisories
    raise AttributeError(name)
