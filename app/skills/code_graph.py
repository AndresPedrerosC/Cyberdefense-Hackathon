"""Code graph skill: which files import which packages, and which HTTP routes reach which files.

A static, regex-level reader for JS/TS (CommonJS, ESM, `import x = require()`) and Express-style
route registration (`app.get(path, ...handlers)`, `router.use(prefix, ...)`). It is pure Python
so reachability works wherever the API runs, with or without semgrep. It reads files only under
the authorized repo root and never follows symlinks.
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from app.correlate.graph import Edge, Node
from app.skills import SkillContext, SkillResult

SRC_EXTS = (".ts", ".js", ".mjs", ".cjs", ".tsx", ".jsx")
SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", "test", "tests", "__tests__",
             "__mocks__", "cypress", "e2e", "spec", ".next", ".nuxt", "out", "vendor", "vagrant",
             "screenshots", "docs", "examples", "scripts"}
MAX_FILES = 4000
MAX_BYTES = 512 * 1024
MAX_ARGS_SCAN = 6000

BUILTINS = {
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "crypto", "dgram",
    "dns", "domain", "events", "fs", "http", "http2", "https", "inspector", "module", "net",
    "os", "path", "perf_hooks", "process", "punycode", "querystring", "readline", "repl",
    "stream", "string_decoder", "timers", "tls", "tty", "url", "util", "v8", "vm",
    "worker_threads", "zlib",
}

IMPORT_FROM = re.compile(
    r"""^[ \t]*import\s+(?:type\s+)?(?P<clause>[^'";]+?)\s+from\s+['"](?P<mod>[^'"]+)['"]""",
    re.M)
IMPORT_BARE = re.compile(r"""^[ \t]*import\s+['"](?P<mod>[^'"]+)['"]""", re.M)
IMPORT_EQ = re.compile(
    r"""^[ \t]*import\s+(?P<name>[\w$]+)\s*=\s*require\(\s*['"](?P<mod>[^'"]+)['"]\s*\)""", re.M)
REQUIRE_ASSIGN = re.compile(
    r"""\b(?:const|let|var)\s+(?P<lhs>[\w$]+|\{[^}]*\})\s*=\s*require\(\s*['"](?P<mod>[^'"]+)"""
    r"""['"]\s*\)(?P<member>(?:\.[\w$]+)*)""")
REQUIRE_ANY = re.compile(r"""\brequire\(\s*['"](?P<mod>[^'"]+)['"]\s*\)""")

ROUTER_DECL = re.compile(
    r"""\b(?:const|let|var)\s+(?P<name>[\w$]+)\s*(?::\s*[\w.<>]+\s*)?=\s*"""
    r"""(?:express\s*\(\s*\)|(?:express\s*\.\s*)?Router\s*\()""")
ROUTE_CALL = re.compile(
    r"""\b(?P<recv>[\w$]+)\s*\.\s*(?P<method>get|post|put|patch|delete|all|use|options|head)"""
    r"""\s*\(""")
DEFAULT_RECEIVERS = {"app", "router", "server", "api", "routes", "apiRouter"}
CALLEE = re.compile(r"""^\s*(?:new\s+)?(?P<head>[\w$]+)(?P<members>(?:\s*\.\s*[\w$]+)*)""")
IDENT = re.compile(r"[A-Za-z_$][\w$]*")
STRING = re.compile(r"""^\s*(['"`])(?P<s>(?:\\.|(?!\1).)*)\1\s*$""", re.S)
STATIC_DIR = re.compile(
    r"""\b(?:serveIndex|serveStatic|static)\s*\(\s*(?:path\s*\.\s*(?:resolve|join)\s*\(\s*)?"""
    r"""(?:__dirname\s*,\s*)?['"](?P<dir>[^'"]+)['"]""")
# Middleware whose name says it gates the request on identity.
AUTH_NAME = re.compile(
    r"^(?:(?:is|ensure|require|check|verify)_?(?:authori[sz]ed|authenticated?|logged_?in|"
    r"signed_?in|auth|jwt|token|admin|role)|authenticate|denyall|expressjwt|jwt|auth)$",
    re.IGNORECASE)


@dataclass
class Binding:
    name: str
    module: str  # package name or repo-relative file
    local: bool
    member: str | None
    line: int


@dataclass
class Route:
    method: str
    path: str
    file: str
    line: int
    handlers: list[str]
    auth_by: str | None = None
    static_dirs: list[str] = field(default_factory=list)
    targets: list[Binding] = field(default_factory=list)
    inline: bool = False

    @property
    def node_id(self) -> str:
        return f"route:{self.method} {self.path}#{self.file}:{self.line}"


@dataclass
class FileInfo:
    rel: str
    bindings: dict[str, Binding] = field(default_factory=dict)
    imports: list[Binding] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)


class CodeGraphSkill:
    name = "code_graph"
    label = "Code paths"

    def applies_to(self, ctx: SkillContext) -> bool:
        return ctx.repo_path is not None

    def run(self, ctx: SkillContext) -> SkillResult:
        files = scan_repo(ctx.repo_path)
        nodes, edges = to_graph(files)
        routes = [r for f in files.values() for r in f.routes]
        return SkillResult(
            name=self.name,
            detail=f"{len(files)} source files, {len(routes)} routes, "
                   f"{sum(1 for e in edges if e.kind == 'imports' and e.dst.startswith('pkg:'))} "
                   "package imports",
            nodes=nodes, edges=edges,
            data={"routes": [_route_dict(r) for r in routes]},
        )


# --------------------------------------------------------------------------- #
# scanning
# --------------------------------------------------------------------------- #

def scan_repo(root: Path) -> dict[str, FileInfo]:
    root = Path(root).resolve()
    out: dict[str, FileInfo] = {}
    nested = _nested_projects(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root)
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")
                             and os.path.normpath(os.path.join(rel_dir, d)) not in nested)
        for fname in sorted(filenames):
            if not fname.endswith(SRC_EXTS) or fname.endswith(".d.ts") or _is_test(fname):
                continue
            path = Path(dirpath) / fname
            if path.is_symlink():
                continue
            try:
                if path.stat().st_size > MAX_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            out[rel] = parse_file(rel, text, root)
            if len(out) >= MAX_FILES:
                return _resolve_mounts(out)
    return _resolve_mounts(out)


def _nested_projects(root: Path) -> set[str]:
    """Sub-folders with their own package.json (e.g. a bundled frontend) are separate apps."""
    nested = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        if "package.json" in filenames and Path(dirpath) != root:
            nested.add(os.path.relpath(dirpath, root))
            dirnames[:] = []
    return nested


def _is_test(fname: str) -> bool:
    return bool(re.search(r"\.(spec|test|e2e)\.[cm]?[jt]sx?$", fname))


def parse_file(rel: str, text: str, root: Path) -> FileInfo:
    info = FileInfo(rel=rel)
    code = _blank_comments(text)

    def add(name: str | None, spec: str, member: str | None, pos: int) -> None:
        target = resolve_module(spec, rel, root)
        if target is None:
            return
        module, local = target
        b = Binding(name=name or "", module=module, local=local, member=member,
                    line=code.count("\n", 0, pos) + 1)
        info.imports.append(b)
        if name:
            info.bindings[name] = b

    for m in IMPORT_FROM.finditer(code):
        for name, member in _import_clause(m.group("clause")):
            add(name, m.group("mod"), member, m.start())
    for m in IMPORT_BARE.finditer(code):
        add(None, m.group("mod"), None, m.start())
    for m in IMPORT_EQ.finditer(code):
        add(m.group("name"), m.group("mod"), None, m.start())
    claimed = set()
    for m in REQUIRE_ASSIGN.finditer(code):
        claimed.add(m.start("mod"))
        member = m.group("member").lstrip(".") or None
        lhs = m.group("lhs")
        if lhs.startswith("{"):
            for name, prop in _destructure(lhs):
                add(name, m.group("mod"), prop, m.start())
        else:
            add(lhs, m.group("mod"), member, m.start())
    for m in REQUIRE_ANY.finditer(code):
        if m.start("mod") not in claimed and not any(
                b.line == code.count("\n", 0, m.start()) + 1 for b in info.imports):
            add(None, m.group("mod"), None, m.start())

    info.routes = parse_routes(rel, code, info.bindings)
    return info


def _blank_comments(text: str) -> str:
    """Replace // and /* */ comments with spaces (newlines kept) so line numbers survive."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c in "'\"`":
            j = _skip_string(text, i)
            out.append(text[i:j])
            i = j
        elif text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _skip_string(text: str, i: int) -> int:
    quote, j, n = text[i], i + 1, len(text)
    while j < n:
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == quote:
            return j + 1
        if text[j] == "\n" and quote != "`":
            return j
        j += 1
    return n


def _import_clause(clause: str) -> list[tuple[str, str | None]]:
    out: list[tuple[str, str | None]] = []
    clause = clause.strip()
    braces = re.search(r"\{([^}]*)\}", clause)
    if braces:
        for part in braces.group(1).split(","):
            part = part.strip().removeprefix("type ").strip()
            if not part:
                continue
            src, _, alias = part.partition(" as ")
            out.append(((alias or src).strip(), src.strip()))
        clause = clause[:braces.start()] + clause[braces.end():]
    star = re.search(r"\*\s+as\s+([\w$]+)", clause)
    if star:
        out.append((star.group(1), None))
        clause = clause[:star.start()] + clause[star.end():]
    default = clause.strip(" ,")
    if default and IDENT.fullmatch(default):
        out.append((default, "default"))
    return out


def _destructure(lhs: str) -> list[tuple[str, str]]:
    out = []
    for part in lhs.strip("{} \n").split(","):
        part = part.strip()
        if not part or part.startswith("..."):
            continue
        prop, _, alias = part.partition(":")
        alias = alias.split("=")[0].strip()
        prop = prop.split("=")[0].strip()
        if IDENT.fullmatch(alias or prop):
            out.append((alias or prop, prop))
    return out


def resolve_module(spec: str, from_rel: str, root: Path) -> tuple[str, bool] | None:
    """(package name, False) or (repo-relative file, True); None for builtins and misses."""
    spec = spec.strip()
    if not spec or spec.startswith("node:"):
        return None
    if spec.startswith("."):
        base = os.path.normpath(os.path.join(os.path.dirname(from_rel), spec))
        if base.startswith(".."):
            return None
        for cand in (base, *(base + e for e in SRC_EXTS),
                     *(os.path.join(base, "index" + e) for e in SRC_EXTS)):
            p = root / cand
            if p.is_file() and not p.is_symlink():
                return cand.replace(os.sep, "/"), True
        return None
    if spec.startswith(("/", "http:", "https:")):
        return None
    parts = spec.split("/")
    name = "/".join(parts[:2]) if spec.startswith("@") and len(parts) > 1 else parts[0]
    if name in BUILTINS:
        return None
    return name, False


# --------------------------------------------------------------------------- #
# routes
# --------------------------------------------------------------------------- #

def parse_routes(rel: str, code: str, bindings: dict[str, Binding]) -> list[Route]:
    receivers = DEFAULT_RECEIVERS | {m.group("name") for m in ROUTER_DECL.finditer(code)}
    routes: list[Route] = []
    for m in ROUTE_CALL.finditer(code):
        if m.group("recv") not in receivers:
            continue
        args = split_args(code, m.end() - 1)
        if not args:
            continue
        method = m.group("method").upper()
        paths = _paths(args[0])
        handlers = args[1:] if paths is not None else args
        if method == "GET" and len(args) < 2:
            continue  # app.get('setting') reads config, it is not a route
        if not handlers:
            continue
        line = code.count("\n", 0, m.start()) + 1
        for path in paths or ["*"]:
            route = Route(method=method, path=path, file=rel, line=line,
                          handlers=[" ".join(h.split())[:160] for h in handlers])
            for h in handlers:
                _read_handler(h, bindings, route)
            routes.append(route)
    return routes


def split_args(code: str, open_paren: int) -> list[str]:
    """Top-level comma-separated arguments of the call whose '(' is at open_paren."""
    depth, i, start = 0, open_paren, open_paren + 1
    end = min(len(code), open_paren + MAX_ARGS_SCAN)
    args: list[str] = []
    while i < end:
        c = code[i]
        if c in "'\"`":
            i = _skip_string(code, i)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                last = code[start:i].strip()
                if last:
                    args.append(last)
                return args
        elif c == "," and depth == 1:
            args.append(code[start:i].strip())
            start = i + 1
        i += 1
    return []


def _paths(arg: str) -> list[str] | None:
    m = STRING.match(arg)
    if m:
        return [m.group("s")]
    if arg.startswith("[") and arg.endswith("]"):
        items = [STRING.match(p) for p in arg[1:-1].split(",")]
        if items and all(items):
            return [i.group("s") for i in items]
    if arg.startswith("/") and arg.rstrip("gimsuy").endswith("/"):
        return [arg]  # regex route
    return None


def _read_handler(expr: str, bindings: dict[str, Binding], route: Route) -> None:
    m = CALLEE.match(expr)
    if m:
        members = [p.strip() for p in m.group("members").split(".") if p.strip()]
        for name in [m.group("head"), *members]:
            if AUTH_NAME.match(name) and not route.auth_by:
                route.auth_by = " ".join(expr.split())[:80]
    for d in STATIC_DIR.finditer(expr):
        route.static_dirs.append(d.group("dir").strip("./"))
    # Identifiers the handler references: drop strings, property names (`.x`) and object
    # keys (`{ x: ... }`) so `{ payment: [...] }` is not read as a use of a `payment` import.
    bare = re.sub(r"(['\"`]).*?\1", "", expr)
    bare = re.sub(r"\.\s*[\w$]+", "", bare)
    bare = re.sub(r"([{,]\s*)[\w$]+\s*:(?!:)", r"\1", bare)
    used = set(IDENT.findall(bare))
    for name in sorted(used):
        b = bindings.get(name)
        if b and all(t.module != b.module for t in route.targets):
            route.targets.append(b)
    if "=>" in expr or expr.lstrip().startswith(("function", "async")):
        route.inline = True


def _resolve_mounts(files: dict[str, FileInfo]) -> dict[str, FileInfo]:
    """`app.use('/api', apiRouter)` where apiRouter is a local file: prefix that file's routes,
    and apply prefix-scoped auth middleware (`app.use('/admin', requireAuth)`) to its routes."""
    for f in files.values():
        for r in f.routes:
            if r.method != "USE" or r.path in ("*", "/"):
                continue
            for t in r.targets:
                sub = files.get(t.module) if t.local else None
                if not sub or sub is f:
                    continue
                for child in sub.routes:
                    if not child.path.startswith(r.path) and child.path != "*":
                        child.path = r.path.rstrip("/") + ("" if child.path == "/" else
                                                           child.path if child.path != "*" else "")
                        child.path = child.path or "/"
                    if r.auth_by and not child.auth_by:
                        child.auth_by = r.auth_by
    for f in files.values():
        gates = [r for r in f.routes if r.method == "USE" and r.auth_by and r.path != "*"]
        for r in f.routes:
            if r.auth_by:
                continue
            for g in gates:
                if g.line < r.line and _under(r.path, g.path):
                    r.auth_by = f"{g.auth_by} on {g.path}"
                    break
    return files


def _under(path: str, prefix: str) -> bool:
    prefix = prefix.rstrip("/")
    return path == prefix or path.startswith(prefix + "/")


# --------------------------------------------------------------------------- #
# graph output
# --------------------------------------------------------------------------- #

def to_graph(files: dict[str, FileInfo]) -> tuple[list[Node], list[Edge]]:
    nodes: list[Node] = []
    edges: list[Edge] = []
    sk = CodeGraphSkill.name
    for f in files.values():
        nodes.append(Node(id=f"file:{f.rel}", kind="file", label=f.rel, skill=sk, data={
            "bindings": {b.name: [b.module, b.member, b.line, b.local]
                         for b in f.bindings.values() if not b.local}}))
        for b in f.imports:
            dst = f"file:{b.module}" if b.local else f"pkg:{b.module}"
            edges.append(Edge(src=f"file:{f.rel}", dst=dst, kind="imports", line=b.line,
                              detail=f"{f.rel}:{b.line} imports {b.module}"
                                     + (f" as {b.name}" if b.name else ""), skill=sk))
        for r in f.routes:
            nodes.append(Node(id=r.node_id, kind="route", label=f"{r.method} {r.path}", skill=sk,
                              data=_route_dict(r)))
            for t in r.targets:
                dst = f"file:{t.module}" if t.local else f"pkg:{t.module}"
                edges.append(Edge(src=r.node_id, dst=dst, kind="handles", line=r.line,
                                  detail=f"{r.method} {r.path} calls {t.name}"
                                         + ("()" if not t.local else f" from {t.module}"),
                                  skill=sk))
            if r.inline:
                edges.append(Edge(src=r.node_id, dst=f"file:{f.rel}", kind="handles",
                                  line=r.line, detail="inline handler", skill=sk))
    return nodes, edges


def _route_dict(r: Route) -> dict:
    return {"method": r.method, "path": r.path, "file": r.file, "line": r.line,
            "handlers": r.handlers, "auth_by": r.auth_by, "static_dirs": r.static_dirs,
            "targets": [t.module for t in r.targets]}


def find_symbol_use(root: Path, rel: str, binding_names: list[str], symbols: list[str]
                    ) -> tuple[str, int] | None:
    """First line in `rel` where a vulnerable symbol is used through the package's binding:
    `binding.symbol(`, `binding(` for a default-export symbol, or a destructured `symbol(`."""
    if not symbols or not binding_names:
        return None
    path = (Path(root) / rel).resolve()
    if not str(path).startswith(str(Path(root).resolve())) or path.is_symlink():
        return None
    try:
        code = _blank_comments(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return None
    for sym in symbols:
        last = sym.split(".")[-1].rstrip("()")
        for b in binding_names:
            pats = [rf"\b{re.escape(b)}\s*(?:\.\s*[\w$]+\s*)*\.\s*{re.escape(last)}\b"]
            if b == last:
                pats.append(rf"(?:\bnew\s+)?\b{re.escape(b)}\s*\(")
            for p in pats:
                m = re.search(p, code)
                if m:
                    return sym, code.count("\n", 0, m.start()) + 1
    return None
