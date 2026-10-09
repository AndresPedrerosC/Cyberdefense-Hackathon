"""Exposure graph: every skill contributes nodes and edges, the correlator walks paths.

Node ids are typed prefixes so skills can point at each other without coordinating:
  pkg:<name>  adv:<id>  file:<repo-relative path>  route:<METHOD path>#<file>:<line>
  ep:<path>  exp:<finding id>  tech:<name>
Edges are directed from the side an attacker enters toward the vulnerable thing:
  route -handles-> file|pkg, file -imports-> file|pkg, pkg -depends_on-> pkg,
  adv -affects-> pkg, ep -serves-> route, file -contains-> exp
"""

from collections import defaultdict

from pydantic import BaseModel, Field


class Node(BaseModel):
    id: str
    kind: str
    label: str
    data: dict = Field(default_factory=dict)
    source_url: str | None = None
    skill: str = ""


class Edge(BaseModel):
    src: str
    dst: str
    kind: str
    detail: str = ""
    line: int | None = None
    skill: str = ""


class Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._out: dict[str, list[Edge]] = defaultdict(list)
        self._in: dict[str, list[Edge]] = defaultdict(list)
        self._seen: set[tuple[str, str, str]] = set()

    def add_node(self, node: Node) -> Node:
        have = self.nodes.get(node.id)
        if have is None:
            self.nodes[node.id] = node
            return node
        have.data.update({k: v for k, v in node.data.items() if v not in (None, "", [], {})})
        have.source_url = have.source_url or node.source_url
        if have.kind == "placeholder":
            have.kind, have.label, have.skill = node.kind, node.label, node.skill
        return have

    def add_edge(self, edge: Edge) -> None:
        key = (edge.src, edge.dst, edge.kind)
        if key in self._seen:
            return
        self._seen.add(key)
        for nid in (edge.src, edge.dst):
            if nid not in self.nodes:
                self.nodes[nid] = Node(id=nid, kind="placeholder", label=nid.split(":", 1)[-1])
        self.edges.append(edge)
        self._out[edge.src].append(edge)
        self._in[edge.dst].append(edge)

    def merge(self, nodes: list[Node], edges: list[Edge]) -> None:
        for n in nodes:
            self.add_node(n)
        for e in edges:
            self.add_edge(e)

    def out_edges(self, nid: str, kind: str | None = None) -> list[Edge]:
        return [e for e in self._out.get(nid, ()) if kind is None or e.kind == kind]

    def in_edges(self, nid: str, kind: str | None = None) -> list[Edge]:
        return [e for e in self._in.get(nid, ()) if kind is None or e.kind == kind]

    def of_kind(self, kind: str) -> list[Node]:
        return [n for n in self.nodes.values() if n.kind == kind]

    def to_dict(self) -> dict:
        return {"nodes": [n.model_dump() for n in self.nodes.values()],
                "edges": [e.model_dump() for e in self.edges]}
