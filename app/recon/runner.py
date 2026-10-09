"""Runs the recon collectors for one domain and keeps the knowledge base snapshot current."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from app import store
from app.recon.ct import collect_subdomains
from app.recon.dns_records import collect_asn, collect_dns, collect_mail
from app.recon.kb import FetchedPage, KnowledgeBase
from app.recon.rdap import collect_rdap
from app.recon.tls import collect_tls
from app.recon.website import collect_website, probe_subdomains
from app.schema import Emit

# Latest KB per run, so the API can serve snapshots without a ClickHouse round trip.
_live: dict[str, KnowledgeBase] = {}
_lock = threading.Lock()


def get_live(run_id: str) -> KnowledgeBase | None:
    return _live.get(run_id)


def save(kb: KnowledgeBase, emit: Emit | None = None) -> None:
    """Persist a snapshot. Collectors may still be mutating the KB, so retry a racing dump."""
    kb.touch()
    with _lock:
        _live[kb.run_id] = kb
        for _ in range(3):
            try:
                doc = kb.model_dump_json()
                break
            except RuntimeError:
                time.sleep(0.05)
        else:
            return
    try:
        store.insert_knowledge(kb.run_id, kb.target_id, kb.status, doc)
    except Exception as e:
        if emit:
            emit("discovery", "warn", f"Knowledge snapshot not saved: {e}", None)


def build_knowledge(kb: KnowledgeBase, emit: Emit) -> list[FetchedPage]:
    """Run every collector, DNS-dependent ones after DNS. Returns fetched pages for fingerprinting."""
    pages: list[FetchedPage] = []
    save(kb, emit)

    def dns_then_mail_asn() -> None:
        collect_dns(kb, emit)
        save(kb, emit)
        collect_mail(kb, emit)
        save(kb, emit)
        collect_asn(kb, emit)

    def subdomains_then_probe() -> list[FetchedPage]:
        collect_subdomains(kb, emit)
        save(kb, emit)
        return probe_subdomains(kb, emit)

    jobs = {
        "dns": dns_then_mail_asn,
        "rdap": lambda: collect_rdap(kb, emit),
        "tls": lambda: collect_tls(kb, emit),
        "website": lambda: collect_website(kb, emit),
        "subdomains": subdomains_then_probe,
    }
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = {pool.submit(fn): name for name, fn in jobs.items()}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                result = fut.result()
                if isinstance(result, list):
                    pages.extend(result)
            except Exception as e:  # collectors should not raise; this is a backstop
                kb.coverage[name] = "failed"
                emit("discovery", "warn", f"Collector {name} crashed: {e}", None)
            save(kb, emit)

    emit("discovery", "info",
         f"Recon finished in {time.perf_counter() - started:.1f}s: {len(kb.facts)} facts, "
         f"{len(kb.subdomains)} subdomains, {len(pages)} pages", None)
    return pages
