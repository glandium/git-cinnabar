import hashlib
from binascii import unhexlify
from collections import OrderedDict
from .changegroup import RawRevChunk
from ..git import NULL_NODE_ID
from ..util import TypedProperty
try:
    from mercurial.mdiff import textdiff
except ImportError:
    from ..bdiff import bdiff as textdiff


class HgObject(object):
    __slots__ = ('node', 'parent1', 'parent2', 'changeset')

    def __init__(self, node=NULL_NODE_ID, parent1=NULL_NODE_ID,
                 parent2=NULL_NODE_ID, changeset=NULL_NODE_ID):
        (self.node, self.parent1, self.parent2, self.changeset) = (
            node, parent1, parent2, changeset)

    @classmethod
    def from_chunk(cls, raw_chunk, delta_object=None):
        assert isinstance(raw_chunk, RawRevChunk)
        assert \
            (delta_object is None and raw_chunk.delta_node == NULL_NODE_ID) or\
            (isinstance(delta_object, cls) and
             raw_chunk.delta_node == delta_object.node)
        return cls(raw_chunk.node, raw_chunk.parent1, raw_chunk.parent2,
                   raw_chunk.changeset)

    def to_chunk(self, raw_chunk_type, delta_object=None):
        assert delta_object is None or isinstance(delta_object, type(self))
        assert issubclass(raw_chunk_type, RawRevChunk)
        raw_chunk = raw_chunk_type()
        node = self.node if self.node != NULL_NODE_ID else self.sha1
        (raw_chunk.node, raw_chunk.parent1, raw_chunk.parent2,
         raw_chunk.changeset) = (node, self.parent1, self.parent2,
                                 self.changeset)
        if delta_object:
            raw_chunk.delta_node = delta_object.node
        raw_chunk.patch = self.diff(delta_object)
        return raw_chunk

    def diff(self, delta_object):
        def flatten(s):
            return s if isinstance(s, str) else str(s)
        return textdiff(flatten(delta_object.raw_data) if delta_object else '',
                        flatten(self.raw_data))

    @property
    def parents(self):
        if self.parent1 != NULL_NODE_ID:
            if self.parent2 != NULL_NODE_ID:
                return (self.parent1, self.parent2)
            return (self.parent1,)
        if self.parent2 != NULL_NODE_ID:
            return (self.parent2,)
        return ()

    @parents.setter
    def parents(self, parents):
        assert isinstance(parents, (tuple, list))
        assert len(parents) <= 2
        if len(parents):
            self.parent1 = parents[0]
        if len(parents) > 1:
            self.parent2 = parents[1]
        else:
            self.parent2 = NULL_NODE_ID
        if not parents:
            self.parent1 = NULL_NODE_ID

    @property
    def sha1(self):
        p1 = unhexlify(self.parent1)
        p2 = unhexlify(self.parent2)
        h = hashlib.sha1(min(p1, p2) + max(p1, p2))
        h.update(self.raw_data)
        return h.hexdigest()

    @property
    def raw_data(self):
        return ''.join(self._data_iter())

    def _data_iter(self):
        raise NotImplementedError(
            '%s._data_iter is not implemented' % self.__class__.__name__)


class File(HgObject):
    __slots__ = ('content', '__weakref__')

    def __init__(self, *args, **kwargs):
        super(File, self).__init__(*args, **kwargs)
        self.content = ''

    @classmethod
    def from_chunk(cls, raw_chunk, delta_file=None):
        this = super(File, cls).from_chunk(raw_chunk, delta_file)
        data = raw_chunk.patch.apply(delta_file.raw_data if delta_file else '')
        if data.startswith('\1\n'):
            _, this.metadata, this.content = data.split('\1\n', 2)
        else:
            this.content = data
        return this

    class Metadata(OrderedDict):
        @classmethod
        def from_str(cls, s):
            return cls(
                l.split(': ', 1)
                for l in s.splitlines()
            )

        @classmethod
        def from_dict(cls, d):
            if isinstance(d, OrderedDict):
                return cls(d)
            return cls(sorted(d.iteritems()))

        @classmethod
        def from_obj(cls, obj):
            if isinstance(obj, dict):
                return cls.from_dict(obj)
            return cls.from_str(obj)

        def __str__(self):
            return ''.join('%s: %s\n' % i for i in self.iteritems())

    metadata = TypedProperty(Metadata)

    def _data_iter(self):
        metadata = str(self.metadata)
        if metadata or self.content.startswith('\1\n'):
            metadata = '\1\n%s\1\n' % metadata
        if metadata:
            yield metadata
        if self.content:
            yield self.content
