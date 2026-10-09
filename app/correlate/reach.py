"""Reachability: how an attacker gets from the outside to a vulnerable package.

For each vulnerable package the correlator asks, in order:
  1. Does any source file import it (or import a package that depends on it)?
  2. Is that file in the handler chain of an HTTP route (route -> handler module -> imports)?
  3. Does the running app answer that route, and without auth?
  4. Does the importing code call the vulnerable API itself?
The answers become a tier (exposed > called > imported > installed) plus the concrete path,
so every claim in a finding points at a route, a file:line or a lockfile edge.
"""

import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from app.correlate.graph import Edge, Graph, Node
from app.schema import PathStep, ReachTier

MAX_FILE_DEPTH = 6
MAX_PARENT_DEPTH = 4


@dataclass
class Option:
    route: Node | None = None
    endpoint: Node | None = None  # live endpoint confirming the route (or the page, publicly)
    chain: list[str] = field(default_factory=list)  # file ids, handler module -> importer
    importer: str | None = None  # file id that imports the package
    edge: Edge | None = None  # the import / handles / loads edge that reaches the package

    @property
    def auth(self) -> bool | None:
        if self.endpoint is not None:
            cls = self.endpoint.data.get("classification")
            if cls == "authenticated":
                return True
            if cls == "public" and not (self.route and self.route.data.get("auth_by")):
                return False
        if self.route is not None:
            return bool(self.route.data.get("auth_by"))
        return None

    def rank(self) -> tuple:
        entry = self.route is not None or self.endpoint is not None
        return (entry, self.auth is False, self.endpoint is not None, -len(self.chain))


@dataclass
class Reach:
    tier: ReachTier
    auth_required: bool | None = None
    via: list[str] = field(default_factory=list)  # parent packages, importer side first
    symbol: str | None = None
    symbol_at: str | None = None  # file:line
    direct_call: bool = False  # the route handler expression calls the package binding itself
    global_middleware: bool = False
    observed_live: bool = False
    route_label: str | None = None
    route_count: int = 0  # how many distinct routes reach the package
    steps: list[PathStep] = field(default_factory=list)


class Reachability:
    def __init__(self, graph: Graph, repo_root: Path | None = None):
        self.g = graph
        self.root = repo_root
        self.endpoints = graph.of_kind("endpoint")
        self.file_routes = self._route_closures()

    # -- precompute ------------------------------------------------------------

    def _route_closures(self) -> dict[str, list[tuple[Node, list[str]]]]:
        """file id -> [(route, shortest file chain from the route's handler to that file)]."""
        out: dict[str, list[tuple[Node, list[str]]]] = {}
        for route in self.g.of_kind("route"):
            seen: dict[str, list[str]] = {}
            q: deque[str] = deque()
            for e in self.g.out_edges(route.id, "handles"):
                if e.dst.startswith("file:") and e.dst not in seen:
                    seen[e.dst] = [e.dst]
                    q.append(e.dst)
            while q:
                fid = q.popleft()
                if len(seen[fid]) >= MAX_FILE_DEPTH:
                    continue
                for e in self.g.out_edges(fid, "imports"):
                    if e.dst.startswith("file:") and e.dst not in seen:
                        seen[e.dst] = seen[fid] + [e.dst]
                        q.append(e.dst)
            for fid, chain in seen.items():
                out.setdefault(fid, []).append((route, chain))
        return out

    # -- assess ----------------------------------------------------------------

    def assess(self, package: str, advisory_id: str, symbols: list[str]) -> Reach:
        pid = f"pkg:{package}"
        pnode = self.g.nodes.get(pid)
        level, chain_pkgs = self._closest_used(pid)
        options: list[Option] = []
        if level is not None:
            options = self._options(level)

        symbol = self._rule_hit(advisory_id) if level == pid else None
        if symbol is None and level == pid and symbols and self.root is not None:
            symbol = self._symbol_use(pid, package, options, symbols)

        reach = Reach(tier="installed")
        reach.via = chain_pkgs
        best = None
        if options:
            if symbol:
                # Prefer an entry point whose chain contains the file that calls the API.
                with_sym = [o for o in options if o.importer == symbol[2] or (
                    o.importer is None and o.edge is not None and o.edge.src == symbol[2])]
                options = with_sym or options
            best = max(options, key=lambda o: o.rank())
            reach.route_count = len({o.route.id for o in options if o.route is not None})

        if best and (best.route is not None or best.endpoint is not None):
            reach.tier = "exposed"
            reach.auth_required = best.auth
            reach.observed_live = best.endpoint is not None
            # Only the package the route calls counts as called directly, not its dependencies.
            reach.direct_call = not chain_pkgs and best.importer is None and (
                best.edge is not None and best.edge.kind in ("handles", "loads"))
            if best.route is not None:
                reach.route_label = best.route.label
                reach.global_middleware = best.route.data.get("path") == "*"
            elif best.endpoint is not None:
                reach.route_label = f"GET {best.endpoint.label}"
        elif symbol:
            reach.tier = "called"
        elif best:
            reach.tier = "imported"
        if symbol:
            reach.symbol, reach.symbol_at = symbol[0], symbol[1]

        reach.steps = self._steps(best, chain_pkgs, pid, pnode, advisory_id, symbol)
        return reach

    def _closest_used(self, pid: str) -> tuple[str | None, list[str]]:
        """The package itself if code uses it, else the nearest ancestor that code uses.
        Returns (that package id, ancestor names from the used one down to pid's parent)."""
        q: deque[tuple[str, list[str]]] = deque([(pid, [])])
        seen = {pid}
        while q:
            cur, chain = q.popleft()
            if self._used(cur):
                return cur, chain
            if len(chain) >= MAX_PARENT_DEPTH:
                continue
            for e in self.g.in_edges(cur, "depends_on"):
                if e.src not in seen:
                    seen.add(e.src)
                    q.append((e.src, [e.src.removeprefix("pkg:")] + chain))
        return None, []

    def _used(self, pid: str) -> bool:
        return any(self.g.in_edges(pid, k) for k in ("imports", "handles", "loads"))

    def _options(self, pid: str) -> list[Option]:
        opts: list[Option] = []
        for e in self.g.in_edges(pid, "handles"):
            route = self.g.nodes[e.src]
            opts.append(Option(route=route, endpoint=self._live(route), edge=e))
        for e in self.g.in_edges(pid, "loads"):
            opts.append(Option(endpoint=self.g.nodes.get(e.src), edge=e))
        for e in self.g.in_edges(pid, "imports"):
            routes = self.file_routes.get(e.src) or []
            if not routes:
                opts.append(Option(importer=e.src, edge=e))
            for route, chain in routes:
                opts.append(Option(route=route, endpoint=self._live(route), chain=chain,
                                   importer=e.src, edge=e))
        return opts

    def _rule_hit(self, advisory_id: str) -> tuple[str, str, str] | None:
        """An advisory-specific semgrep rule that matched counts as a confirmed call."""
        for e in self.g.in_edges(f"adv:{advisory_id}", "calls"):
            rel = e.src.removeprefix("file:")
            return "rule match", f"{rel}:{e.line}", e.src
        return None

    def _symbol_use(self, pid: str, package: str, options: list[Option],
                    symbols: list[str]) -> tuple[str, str, str] | None:
        from app.skills.code_graph import find_symbol_use

        files = {o.importer for o in options if o.importer} | {
            o.edge.src for o in options if o.edge is not None and o.edge.kind == "imports"}
        for fid in sorted(files):
            node = self.g.nodes.get(fid)
            names = [n for n, b in (node.data.get("bindings") or {}).items()
                     if b and b[0] == package] if node else []
            rel = fid.removeprefix("file:")
            hit = find_symbol_use(self.root, rel, names, symbols)
            if hit:
                return hit[0], f"{rel}:{hit[1]}", fid
        return None

    def _live(self, route: Node) -> Node | None:
        path = route.data.get("path") or ""
        if not self.endpoints or not path.startswith("/"):
            return None
        rx = _route_regex(path, prefix=route.data.get("method") == "USE")
        hits = [ep for ep in self.endpoints if rx.match(ep.label)]
        hits.sort(key=lambda ep: ep.data.get("classification") != "public")
        return hits[0] if hits else None

    # -- evidence path -----------------------------------------------------------

    def _steps(self, best: Option | None, chain_pkgs: list[str], pid: str, pnode: Node | None,
               advisory_id: str, symbol) -> list[PathStep]:
        steps: list[PathStep] = []
        if best is not None:
            if best.endpoint is not None:
                ep = best.endpoint
                cls = ep.data.get("classification") or "seen"
                steps.append(PathStep(node_id=ep.id, kind="endpoint", label=ep.label,
                                      detail=f"live: {cls}", source_url=ep.source_url))
            if best.route is not None:
                r = best.route
                gate = r.data.get("auth_by")
                where = f"{r.data.get('file')}:{r.data.get('line')}"
                detail = f"registered at {where}" + (f", behind {gate}" if gate else ", no auth "
                                                     "middleware")
                if r.data.get("path") == "*":
                    detail = f"global middleware at {where}, runs on every request"
                steps.append(PathStep(node_id=r.id, kind="route", label=r.label, detail=detail))
            prev = None
            for fid in best.chain:
                detail = "route handler module" if prev is None else self._import_detail(prev,
                                                                                          fid)
                steps.append(PathStep(node_id=fid, kind="file", label=fid.removeprefix("file:"),
                                      detail=detail))
                prev = fid
            if best.importer and best.importer not in best.chain:
                steps.append(PathStep(node_id=best.importer, kind="file",
                                      label=best.importer.removeprefix("file:")))
            if best.edge is not None and steps:
                used = chain_pkgs[0] if chain_pkgs else pid.removeprefix("pkg:")
                if best.edge.kind == "imports":
                    note = f"line {best.edge.line} imports {used}"
                elif best.edge.kind == "loads":
                    note = best.edge.detail
                else:
                    note = f"handler calls {used} directly"
                last = steps[-1]
                last.detail = f"{last.detail}; {note}" if last.detail else note
            if symbol:
                steps.append(PathStep(node_id=symbol[2], kind="call", label=symbol[0],
                                      detail=f"called at {symbol[1]}"))
        for name in chain_pkgs:
            n = self.g.nodes.get(f"pkg:{name}")
            steps.append(PathStep(node_id=f"pkg:{name}", kind="package", label=name,
                                  detail=f"{name}@{(n.data.get('version') if n else '') or '?'} "
                                         "depends on the next package"))
        if pnode is not None:
            d = pnode.data
            where = "dev dependency only" if d.get("dev") else (
                "direct dependency" if d.get("direct") else "transitive dependency")
            steps.append(PathStep(node_id=pid, kind="package", label=pnode.label,
                                  detail=f"{pnode.label}@{d.get('version') or '?'}, {where}",
                                  source_url=pnode.source_url))
        adv = self.g.nodes.get(f"adv:{advisory_id}")
        steps.append(PathStep(node_id=f"adv:{advisory_id}", kind="advisory", label=advisory_id,
                              detail=(adv.data.get("summary") or "") if adv else "",
                              source_url=adv.source_url if adv else None))
        return steps

    def _import_detail(self, src: str, dst: str) -> str:
        for e in self.g.out_edges(src, "imports"):
            if e.dst == dst:
                return f"imported by {src.removeprefix('file:')}:{e.line}"
        return ""


def _route_regex(path: str, prefix: bool = False) -> re.Pattern:
    """Express path -> regex over observed paths. `:param` is one segment; USE matches a prefix."""
    segs = [s for s in path.strip("/").split("/") if s]
    parts = [r"[^/]+" if s.startswith(":") else ".*" if "*" in s else re.escape(s)
             for s in segs]
    body = "/" + "/".join(parts) if parts else ""
    return re.compile("^" + body + (r"(?:/.*)?$" if prefix else r"/?$"))
