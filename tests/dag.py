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
        self.assertEqual(set(self.dag.heads()), set('EGHIJ'))

    def test_tag_nodes_and_parents(self):
        self.dag.tag_nodes_and_parents('CD', 'foo')
        self.assertEqual(set(self.dag.heads('foo')), set('CD'))
        self.assertEqual(set(self.dag.heads()), set('EGHIJ'))

        # Using a different tag for already tagged nodes doesn't change
        # anything
        self.dag.tag_nodes_and_parents('CD', 'bar')
        self.assertEqual(set(self.dag.heads('bar')), set())
        self.assertEqual(set(self.dag.heads()), set('EGHIJ'))

    def test_tag_nodes_and_parents_2(self):
        self.dag.tag_nodes_and_parents('F', 'foo')
        self.assertEqual(set(self.dag.heads('foo')), set('F'))
        self.assertEqual(set(self.dag.heads()), set('EGHIJ'))

        self.dag.tag_nodes_and_parents('GHIJ', 'bar')
        self.assertEqual(set(self.dag.heads('foo')), set('F'))
        self.assertEqual(set(self.dag.heads('bar')), set('GHIJ'))
        self.assertEqual(set(self.dag.heads()), set('E'))

        self.dag.tag_nodes_and_parents('E', 'baz')
        self.assertEqual(set(self.dag.heads()), set())
