"""Helper functions shared across tests."""

from datetime import datetime

import aenum
from gremlin_python.process.traversal import T, Direction


def clean_blacklist(obj):
    """Given a dict representing a vertex or edge of a graph, removes the
    fields that should not be compared in tests."""
    blacklist = [
        T.id,
        Direction.IN,
        Direction.OUT,
        "scan_id",
        "timestamp",
        "creation_date",
        "start_time",
        "end_time",
        "creation_time",
        "create_time",
    ]

    for field in blacklist:
        if field in obj:
            del obj[field]


def translate(obj):
    """Translates a graph into a "comparable" graph, which can be compared and
    stored as JSON."""
    if isinstance(obj, dict):
        clean_blacklist(obj)
        return {translate(k): translate(v) for k, v in obj.items()}

    if isinstance(obj, list):
        return list(translate(x) for x in obj)

    if isinstance(obj, datetime):
        return obj.isoformat()

    if isinstance(obj, set):
        return set(translate(x) for x in obj)

    if isinstance(obj, aenum.Enum):
        return str(obj)

    return obj


def get_vertex(vertices, vid):
    """Gets a vertex given its vertex ID."""
    for v in vertices:
        if v[T.id] == vid:
            return v
    raise Exception("Node not found")


def create_graph(vertices, edges):
    """Creates a "comparable" graph from a set of Gremlin vertices and
    edges."""
    graph = []
    for e in edges:
        e["T.v_in"] = get_vertex(vertices, e[Direction.IN][T.id])
        e["T.v_out"] = get_vertex(vertices, e[Direction.OUT][T.id])
        graph.append(e)
    return translate(graph)


def compare_graphs(graph1, graph2):
    """Compares two graphs."""
    assert len(graph1) == len(graph2)
    for i in graph1:
        assert i in graph2
