"""Gremlin DSL for the Security Graph Altimeter Universe."""

from datetime import datetime
import uuid

from gremlin_python.process.graph_traversal import (
    GraphTraversal,
    GraphTraversalSource,
    __ as AnonymousTraversal,
)
from gremlin_python.process.traversal import (
    T,
    Cardinality,
    Bytecode,
)


class AltimeterTraversal(GraphTraversal):
    """Graph Traversal for the Altimeter Universe."""

    def link_to_universe(self, universe):
        """Creates an edge from the vertices in the traversal to the current
        universe vertex."""
        return self \
            .sideEffect(
              __.addE('universe_of')
              .from_(__.V().is_universe_obj(universe))
            )

    def is_universe(self):
        """Filters the vertices that are Universes."""
        return self \
            .hasLabel('Universe')

    def is_universe_obj(self, universe):
        """Filters the Universe vertex with a given version and
        namespace."""
        return self \
            .is_universe() \
            .has('namespace', universe.namespace) \
            .has('version', universe.version.int_version)

    def linked_universe(self):
        """Returns the ``Universe`` associated with a vertex."""
        return self \
            .inE() \
            .is_universe_of() \
            .outV()

    def is_linked_to_universe(self, universe):
        """Returns the ``Universe`` vertex associated with a vertex only if it
        matches the specified universe."""
        return self \
            .linked_universe() \
            .is_universe_obj(universe)

    def is_universe_of(self):
        """Filters edges of type ``universe_of``."""
        return self.hasLabel('universe_of')


class __(AnonymousTraversal):
    """Anonymous Traversal for the Altimeter Universe."""

    graph_traversal = AltimeterTraversal

    @classmethod
    def link_to_universe(cls, *args):
        """Creates an edge from the vertices in the transversal to the current
        universe vertex."""
        return cls.graph_traversal(
            None, None, Bytecode()).link_to_universe(*args)

    @classmethod
    def is_universe(cls, *args):
        """Filters the vertices that are Altimeter Universes."""
        return cls.graph_traversal(
            None, None, Bytecode()).is_universe(*args)

    @classmethod
    def is_universe_obj(cls, *args):
        """Filters the Altimeter Universe with a given version and
        namespace."""
        return cls.graph_traversal(
            None, None, Bytecode()).is_universe(*args)

    @classmethod
    def is_linked_to_universe(cls, *args):
        """Returns the ``Universe`` vertex associated with a vertex only if it
        matches the specified universe."""
        return cls.graph_traversal(
            None, None, Bytecode()).is_linked_to_universe(*args)

    @classmethod
    def is_universe_of(cls):
        """Filters edges of type ``universe_of``."""
        return cls.graph_traversal(
            None, None, Bytecode()).is_universe_of()


class AltimeterTraversalSource(GraphTraversalSource):
    """Graph Traversal Source for the Altimeter Universe."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.graph_traversal = AltimeterTraversal

    def ensure_universe(self, universe):
        """Creates a new  Altimeter ``Universe`` vertex, if it doesn't
        exist, and returns its id."""
        return self \
            .V() \
            .is_universe_obj(universe) \
            .fold() \
            .coalesce(
                # The universe vertex already exists.
                __.unfold()
                .elementMap(),
                # The universe vertex does not exist.
                __.addV('Universe')
                .property(T.id, str(uuid.uuid4()))
                .property(
                    Cardinality.single,
                    'namespace',
                    universe.namespace
                )
                .property(
                    Cardinality.single,
                    'version',
                    universe.version.int_version
                )
                .elementMap(),
            )

    def linked_universe(self, vid):
        """Returns a ``Universe`` vertex associated with the vertex identified
        by the vertex id ``vid``."""
        ret = self \
            .V(vid) \
            .linked_universe()
        return ret

    def universe(self, universe):
        """Returns the ``Universe`` vertex that corresponds to specified
        universe."""
        return self\
            .V() \
            .is_universe_obj(universe)

    def link_to_universe(self, universe, vid):
        """Links a given ``Universe`` to the specified vertex"""
        return self\
            .V(vid) \
            .link_to_universe(universe)

    def add_snapshot(self, vid, universe):
        """Creates a new  Snapshot vertex with the given vid, links it to the
        given universe and returns the newly created vertex."""
        return self \
            .addV('altimeter_snapshot') \
            .property(T.id, vid) \
            .property(Cardinality.single, 'timestamp', datetime.now()) \
            .link_to_universe(universe)
