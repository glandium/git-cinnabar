#!/usr/bin/env python2.7

from __future__ import division
from collections import (
    deque,
    defaultdict
)
from .util import OrderedDefaultDict


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

    def roots(self, tag=None):
        for node, parents in self._parents.iteritems():
            if self._tags.get(node) == tag:
                if all(p not in self._parents or self._tags.get(p) != tag
                       for p in parents):
                    yield node

    def heads(self, tag=None):
        for node in self._parents:
            if self._tags.get(node) == tag:
                if (node not in self._children or
                        all(self._tags.get(c) != tag
                            for c in self._children[node])):
                    yield node

    def all_heads(self, with_tags=True):
        if with_tags:
            for node in self._parents:
                tag = self._tags.get(node)
                if (node not in self._children or
                        all(self._tags.get(c) != tag
                            for c in self._children[node])):
                    yield tag, node
        else:
            for node in self._parents:
                if node not in self._children:
                    yield node

    def tag_nodes_and_parents(self, nodes, tag):
        self._tag_nodes_and_other(self._parents, nodes, tag)

    def tag_nodes_and_children(self, nodes, tag):
        self._tag_nodes_and_other(self._children, nodes, tag)

    def _tag_nodes_and_other(self, other, nodes, tag):
        assert tag
        queue = deque(nodes)
        while queue:
            node = queue.popleft()
            if node in self._tags:
                continue
            self._tags[node] = tag
            for o in other.get(node, ()):
                queue.append(o)

    def iternodes(self, tag=None):
        if tag is None:
            for n in self._parents:
                if n not in self._tags:
                    yield n
        else:
            for n, t in self._tags.iteritems():
                if t == tag:
                    yield n

    def __len__(self):
        return len(self._parents)

    def __contains__(self, node):
        return node in self._parents

    def tags(self):
        return set(self._tags.itervalues())
