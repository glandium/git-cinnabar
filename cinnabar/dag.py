from collections import (
    deque,
    defaultdict
)
from cinnabar.util import OrderedDefaultDict


# TODO: this class sucks and is probably wrong
class gitdag(object):
    __slots__ = "_parents", "_children", "_tags"

    def __init__(self, revlist=[]):
        self._parents = OrderedDefaultDict(set)
        self._children = defaultdict(set)
        for node, parents in revlist:
            self._parents[node] |= set(parents)
            for p in parents:
                self._children[p].add(node)
        self._tags = {}

    def add(self, node, parents, tag=None):
        self._parents[node] |= set(parents)
        for p in parents:
            self._children[p].add(node)
        if tag:
            self._tags[node] = tag

    def tag_nodes_and_parents(self, nodes, tag):
        assert tag
        queue = deque(nodes)
        while queue:
            node = queue.popleft()
            if node in self._tags:
                continue
            self._tags[node] = tag
            for o in self._parents.get(node, ()):
                queue.append(o)
