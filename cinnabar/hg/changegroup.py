from binascii import (
    hexlify,
    unhexlify,
)
import struct
import types
from cinnabar.githg import (
    ChangesetInfo,
    ManifestInfo,
    RevChunk,
)
from cinnabar.git import NULL_NODE_ID


class RawRevChunk(bytearray):
    __slots__ = ()

    @staticmethod
    def _field(offset, size=None, filter=str):
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
                    obj.extend('\0' * (length - len(obj)))

        return descriptor()


class RawRevChunk01(RawRevChunk):
    __slots__ = ()

    node = RawRevChunk._field(0, 20, hexlify)
    parent1 = RawRevChunk._field(20, 20, hexlify)
    parent2 = RawRevChunk._field(40, 20, hexlify)
    changeset = RawRevChunk._field(60, 20, hexlify)
    data = RawRevChunk._field(80)

    # Because we keep so many instances of this class on hold, the overhead
    # of having a __dict__ per instance is a deal breaker.
    _delta_nodes = {}

    @property
    def delta_node(self):
        return self._delta_nodes.get(self.node, NULL_NODE_ID)

    @delta_node.setter
    def delta_node(self, value):
        self._delta_nodes[self.node] = value

    def __del__(self):
        try:
            del self._delta_nodes[self.node]
        except KeyError:
            pass


class RawRevChunk02(RawRevChunk):
    __slots__ = ()

    node = RawRevChunk._field(0, 20, hexlify)
    parent1 = RawRevChunk._field(20, 20, hexlify)
    parent2 = RawRevChunk._field(40, 20, hexlify)
    delta_node = RawRevChunk._field(60, 20, hexlify)
    changeset = RawRevChunk._field(80, 20, hexlify)
    data = RawRevChunk._field(100)


def get_previous(store, sha1, type):
    if issubclass(type, ChangesetInfo):
        return store.changeset(sha1)
    if issubclass(type, ManifestInfo):
        return store.manifest(sha1)
    return store.file(sha1)


def prepare_chunk(store, chunk, previous, chunk_type):
    if chunk_type == RawRevChunk01:
        if previous is None and chunk.parent1 != NULL_NODE_ID:
            previous = get_previous(store, chunk.parent1, type(chunk))
        return chunk.serialize(previous, chunk_type)
    elif chunk_type == RawRevChunk02:
        parents = (previous if previous and p == previous.node
                   else get_previous(store, p, type(chunk))
                   for p in chunk.parents)
        deltas = sorted((chunk.serialize(p, chunk_type) for p in parents),
                        key=len)
        if len(deltas):
            return deltas[0]
        else:
            return chunk.serialize(None, chunk_type)
    else:
        assert False


def create_changegroup(store, bundle_data, type=RawRevChunk01):
    previous = None
    for chunk in bundle_data:
        if isinstance(chunk, RevChunk):
            data = prepare_chunk(store, chunk, previous, type)
        else:
            data = chunk
        size = 0 if data is None else len(data) + 4
        yield struct.pack(">l", size)
        if data:
            yield str(data)
        if isinstance(chunk, (RevChunk, types.NoneType)):
            previous = chunk
