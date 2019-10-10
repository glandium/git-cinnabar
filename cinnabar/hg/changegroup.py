from __future__ import absolute_import, unicode_literals
from binascii import (
    hexlify,
    unhexlify,
)
import struct
from cinnabar.git import NULL_NODE_ID


class ParentsTrait(object):
    __slots__ = ()

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


class RevDiff(object):
    class Part(object):
        __slots__ = ('start', 'end', 'block_len', 'text_data')

        def __init__(self, rev_patch):
            self.start, self.end, self.block_len = \
                struct.unpack('>lll', rev_patch[:12].tobytes())
            self.text_data = rev_patch[12:12 + self.block_len]

        def __len__(self):
            return self.block_len + 12

    def __init__(self, buf):
        self._buf = memoryview(buf)

    def __iter__(self):
        start = 0
        while start < len(self._buf):
            part = self.Part(self._buf[start:])
            yield part
            start += len(part)

    def apply(self, raw_orig):
        new = bytearray()
        orig = memoryview(raw_orig)
        end = 0
        for diff in self:
            new += orig[end:diff.start]
            new += diff.text_data
            end = diff.end
        if new == b'' and end == 0:
            return raw_orig
        new += orig[end:]
        return bytes(new)


class RawRevChunk(bytearray, ParentsTrait):
    __slots__ = ()

    @staticmethod
    def _field(offset, size=None, filter=bytes):
        unfilter = unhexlify if filter == hexlify else None
        end = offset + size if size else None

        class descriptor(object):
            def __get__(self, obj, type=None):
                return filter(obj[offset:end])

            def __set__(self, obj, value):
                value = unfilter(value) if unfilter else value
                assert len(value) == size or not size
                self.ensure(obj, end or offset)
                obj[offset:end] = value

            def ensure(self, obj, length):
                if length > len(obj):
                    obj.extend(b'\0' * (length - len(obj)))

        return descriptor()


class RawRevChunk01(RawRevChunk):
    __slots__ = ('__weakref__',)

    node = RawRevChunk._field(0, 20, hexlify)
    parent1 = RawRevChunk._field(20, 20, hexlify)
    parent2 = RawRevChunk._field(40, 20, hexlify)
    changeset = RawRevChunk._field(60, 20, hexlify)
    data = RawRevChunk._field(80)
    patch = RawRevChunk._field(80, filter=RevDiff)

    # Because we keep so many instances of this class on hold, the overhead
    # of having a __dict__ per instance is a deal breaker.
    _delta_nodes = {}

    @property
    def delta_node(self):
        return self._delta_nodes.get(self.node, NULL_NODE_ID)

    @delta_node.setter
    def delta_node(self, value):
        self._delta_nodes[self.node] = value


class RawRevChunk02(RawRevChunk):
    __slots__ = ()

    node = RawRevChunk._field(0, 20, hexlify)
    parent1 = RawRevChunk._field(20, 20, hexlify)
    parent2 = RawRevChunk._field(40, 20, hexlify)
    delta_node = RawRevChunk._field(60, 20, hexlify)
    changeset = RawRevChunk._field(80, 20, hexlify)
    data = RawRevChunk._field(100)
    patch = RawRevChunk._field(100, filter=RevDiff)
