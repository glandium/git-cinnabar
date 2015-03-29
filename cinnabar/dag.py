#!/usr/bin/env python2.7

from __future__ import division
from collections import (
    deque,
    defaultdict
)
import unittest
from .util import OrderedDefaultDict


# TODO: this class sucks and is probably wrong
class gitdag(object):
    def __init__(self, revlist=[]):
        def iter_revlist(revlist):
            for line in revlist:
                line = line.split(' ', 1)
                if len(line) == 1:
                    yield line[0], ()
                else:
                    yield line[0], line[1].split(' ')

        self._parents = OrderedDefaultDict(set)
        self._children = defaultdict(set)
        for node, parents in iter_revlist(revlist):
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
                if (node not in self._children
                        or all(self._tags.get(c) != tag
                               for c in self._children[node])):
                    yield node

    def all_heads(self, with_tags=True):
        if with_tags:
            for node in self._parents:
                tag = self._tags.get(node)
                if (node not in self._children
                        or all(self._tags.get(c) != tag
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

    def tags(self):
        return set(self._tags.itervalues())


class TestDag(unittest.TestCase):
    def setUp(self):
        self.dag = gitdag([
            'B A',
            'C A',
            'D B',
            'E B',
            'F B C',
            'G D',
            'H D',
            'I F',
            'J F',
        ])

    def test_dag(self):
        self.assertEqual(set(self.dag.roots()), set('BC'))
        self.assertEqual(set(self.dag.heads()), set('EGHIJ'))

    def test_tag_nodes_and_parents(self):
        self.dag.tag_nodes_and_parents('CD', 'foo')
        self.assertEqual(set(self.dag.roots('foo')), set('BC'))
        self.assertEqual(set(self.dag.heads('foo')), set('CD'))
        self.assertEqual(set(self.dag.roots()), set('EFGH'))
        self.assertEqual(set(self.dag.heads()), set('EGHIJ'))

        # Using a different tag for already tagged nodes doesn't change
        # anything
        self.dag.tag_nodes_and_parents('CD', 'bar')
        self.assertEqual(set(self.dag.roots('bar')), set())
        self.assertEqual(set(self.dag.heads('bar')), set())
        self.assertEqual(set(self.dag.roots()), set('EFGH'))
        self.assertEqual(set(self.dag.heads()), set('EGHIJ'))

    def test_tag_nodes_and_parents_2(self):
        self.dag.tag_nodes_and_parents('F', 'foo')
        self.assertEqual(set(self.dag.roots('foo')), set('BC'))
        self.assertEqual(set(self.dag.heads('foo')), set('F'))
        self.assertEqual(set(self.dag.roots()), set('DEIJ'))
        self.assertEqual(set(self.dag.heads()), set('EGHIJ'))

        self.dag.tag_nodes_and_parents('GHIJ', 'bar')
        self.assertEqual(set(self.dag.roots('foo')), set('BC'))
        self.assertEqual(set(self.dag.heads('foo')), set('F'))
        self.assertEqual(set(self.dag.roots('bar')), set('DIJ'))
        self.assertEqual(set(self.dag.heads('bar')), set('GHIJ'))
        self.assertEqual(set(self.dag.roots()), set('E'))
        self.assertEqual(set(self.dag.heads()), set('E'))

        self.dag.tag_nodes_and_parents('E', 'baz')
        self.assertEqual(set(self.dag.roots()), set())
        self.assertEqual(set(self.dag.heads()), set())

    def test_tag_nodes_and_children(self):
        self.dag.tag_nodes_and_children('CD', 'foo')
        self.assertEqual(set(self.dag.roots('foo')), set('CD'))
        self.assertEqual(set(self.dag.heads('foo')), set('GHIJ'))
        self.assertEqual(set(self.dag.roots()), set('B'))
        self.assertEqual(set(self.dag.heads()), set('E'))

        # Using a different tag for already tagged nodes doesn't change
        # anything
        self.dag.tag_nodes_and_children('CD', 'bar')
        self.assertEqual(set(self.dag.roots('bar')), set())
        self.assertEqual(set(self.dag.heads('bar')), set())
        self.assertEqual(set(self.dag.roots()), set('B'))
        self.assertEqual(set(self.dag.heads()), set('E'))

    def test_tag_nodes_and_children_2(self):
        self.dag.tag_nodes_and_children('C', 'foo')
        self.assertEqual(set(self.dag.roots('foo')), set('C'))
        self.assertEqual(set(self.dag.heads('foo')), set('IJ'))
        self.assertEqual(set(self.dag.roots()), set('B'))
        self.assertEqual(set(self.dag.heads()), set('EGH'))

        self.dag.tag_nodes_and_children('B', 'bar')
        self.assertEqual(set(self.dag.roots('foo')), set('C'))
        self.assertEqual(set(self.dag.heads('foo')), set('IJ'))
        self.assertEqual(set(self.dag.roots('bar')), set('B'))
        self.assertEqual(set(self.dag.heads('bar')), set('EGH'))
        self.assertEqual(set(self.dag.roots()), set())
        self.assertEqual(set(self.dag.heads()), set())
