#!/usr/bin/env python2.7

from __future__ import division
from collections import (
    deque,
)
import logging
import sys

# TODO: this class sucks and is probably wrong
class gitdag(object):
    class node(object):
        def __init__(self):
            self.parents = None
            self.children = set()

        def __repr__(self):
            return '<p:%s c:%s>' % (self.parents, self.children)

    def __init__(self, revlist=[]):
        def iter_revlist(revlist):
            for line in revlist:
                line = line.split(' ', 1)
                if len(line) == 1:
                    yield line[0], ()
                else:
                    yield line[0], line[1].split(' ')

        self._nodes = {}
        for node, parents in iter_revlist(revlist):
            self.insert(node, parents)
        self._update()

    def _update(self):
        self.roots = set()
        self.heads = set()
        for id, node in self._nodes.iteritems():
            if node.parents is not None and \
                    all(self._nodes[p].parents is None for p in node.parents):
                self.roots.add(id)
            if not node.children:
                self.heads.add(id)

        logging.info('dag size: %d' % len(self))
        logging.info('heads: %d' % len(self.heads))
        logging.info('roots: %d' % len(self.roots))

    def insert(self, node, parents=()):
        if node not in self._nodes:
            self._nodes[node] = self.node()
        if parents is None:
            self._nodes[node].parents = None
            return
        self._nodes[node].parents = set(parents)
        for p in parents:
            if p not in self._nodes:
                self._nodes[p] = self.node()
            self._nodes[p].children.add(node)

    def __iter__(self):
        return iter(self._nodes)

    def __len__(self):
        return len(self._nodes)

    def remove_nodes_and_parents(self, nodes):
        visited = set()
        queue = deque(nodes)
        while queue:
            node = queue.popleft()
            if node in visited:
                continue
            visited.add(node)
            if not self._nodes[node].parents:
                continue
            for p in self._nodes[node].parents:
                queue.append(p)

        for id in visited:
            node = self._nodes[id]
            yield id, node.parents and list(node.parents)
        self.remove(visited)

    def remove_nodes_and_children(self, nodes):
        visited = set()
        queue = deque(nodes)
        while queue:
            node = queue.popleft()
            if node in visited:
                continue
            visited.add(node)
            if not self._nodes[node].children:
                continue
            for c in self._nodes[node].children:
                queue.append(c)

        for id in visited:
            node = self._nodes[id]
            yield id, node.parents and list(node.parents)
        self.remove(visited)

    def remove(self, nodes):
        cleanup = []
        for id in nodes:
            node = self._nodes[id]
            if node.parents:
                for p in node.parents:
                    cleanup.append((p, self._nodes[p].children, id))
            for c in node.children:
                cleanup.append((c, self._nodes[c].parents, id))
        for n, l, id in cleanup:
            if id not in l:
                print >>sys.stderr, n, id, l
            l.remove(id)
        for id in nodes:
            del self._nodes[id]
        self._update()
