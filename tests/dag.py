import unittest
from cinnabar.dag import gitdag


class TestDag(unittest.TestCase):
    def setUp(self):
        self.dag = gitdag([
            ('B', ('A',)),
            ('C', ('A',)),
            ('D', ('B',)),
            ('E', ('B',)),
            ('F', ('B', 'C')),
            ('G', ('D',)),
            ('H', ('D',)),
            ('I', ('F',)),
            ('J', ('F',)),
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
