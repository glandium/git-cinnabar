from __future__ import division
import hashlib
import re
from binascii import unhexlify
from collections import OrderedDict
from types import StringTypes
from .changegroup import (
    ParentsTrait,
    RawRevChunk,
)
from ..git import NULL_NODE_ID
from ..util import (
    check_enabled,
    TypedProperty,
)

try:
    if check_enabled('no-mercurial'):
        raise ImportError('Do not use mercurial')
    from mercurial.mdiff import textdiff  # noqa: F401
except ImportError:
    from ..bdiff import bdiff as textdiff  # noqa: F401


class Authorship(object):
    __slots__ = ('name', 'email', 'timestamp', 'utcoffset')

    WHO_RE = re.compile(r'^(?P<name>.*?) ?(?:\<(?P<email>.*?)\>)')

    @classmethod
    def from_hg_str(cls, s, maybe_git_utcoffset=False):
        return cls.from_hg(*s.rsplit(' ', 2),
                           maybe_git_utcoffset=maybe_git_utcoffset)

    @classmethod
    def from_hg(cls, who, timestamp, utcoffset, maybe_git_utcoffset=False):
        match = cls.WHO_RE.match(who)

        def cleanup(x):
            return x.replace('<', '').replace('>', '')

        if match:
            name = cleanup(match.group('name'))
            email = cleanup(match.group('email'))
        elif '@' in who:
            name = ''
            email = cleanup(who)
        else:
            name = cleanup(who)
            email = ''

        # The UTC offset in mercurial author info is in seconds, formatted as
        # %d. It also has an opposite sign compared to traditional UTC offsets.
        # However, committer info stored in mercurial by hg-git can have
        # git-style UTC offsets, in the form [+-]hhmm.

        # When what we have is in the form +xxxx or -0yyy, it is obviously the
        # latter. When it's -1yyy, it could be either, so we assume that a
        # valid UTC offset is always a multiple of 15 minutes. By that
        # definition, a number between -1000 and -1800 can't be simultaneously
        # a valid UTC offset in seconds and a valid UTC offset in hhmm form.

        # (cf. https://en.wikipedia.org/wiki/List_of_UTC_time_offsets lists
        # there exist a few 15-minutes aligned time zones, but they don't match
        # anything that could match here anyways, but just in case someone one
        # day creates one, assume it won't be finer grained)
        if maybe_git_utcoffset and isinstance(utcoffset, StringTypes):
            is_git = False
            if utcoffset.startswith(('+', '-0')):
                is_git = True
            elif utcoffset.startswith('-1'):
                utcoffset = int(utcoffset)
                if (utcoffset > -1800 and utcoffset % 900 != 0 and
                        (utcoffset % 100) % 15 == 0):
                    is_git = True
            if is_git:
                return cls.from_git('%s <%s>' % (name, email),
                                    timestamp, utcoffset)

        result = cls()
        result.name = name
        result.email = email
        result.timestamp = int(timestamp)
        result.utcoffset = int(utcoffset)
        return result

    @classmethod
    def from_git_str(cls, s):
        return cls.from_git(*s.rsplit(' ', 2))

    @classmethod
    def from_git(cls, who, timestamp, utcoffset):
        result = cls()
        match = cls.WHO_RE.match(who)
        # We don't ever expect a git `who` information to not match the regexp,
        # as git is very conservative in what it accepts.
        assert match
        result.name = match.group('name')
        result.email = match.group('email')
        result.timestamp = int(timestamp)
        utcoffset = int(utcoffset)
        sign = -cmp(utcoffset, 0)
        utcoffset = abs(utcoffset)
        utcoffset = (utcoffset // 100) * 60 + (utcoffset % 100)
        result.utcoffset = sign * utcoffset * 60
        return result

    def to_git(self):
        sign = '+' if self.utcoffset <= 0 else '-'
        utcoffset = abs(self.utcoffset) // 60
        utcoffset = '%c%02d%02d' % (sign, utcoffset // 60, utcoffset % 60)
        who = '%s <%s>' % (self.name, self.email)
        return who, str(self.timestamp), utcoffset

    def to_git_str(self):
        return ' '.join(self.to_git())

    def to_hg(self):
        if self.name and self.email:
            who = '%s <%s>' % (self.name, self.email)
        else:
            who = self.name or '<%s>' % self.email
        return who, str(self.timestamp), str(self.utcoffset)

    def to_hg_str(self):
        return ' '.join(self.to_hg())


class HgObject(ParentsTrait):
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
        self.metadata = {}

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


class Changeset(HgObject):
    __slots__ = ('manifest', 'author', 'timestamp', 'utcoffset', 'body',
                 '__weakref__')

    def __init__(self, *args, **kwargs):
        super(Changeset, self).__init__(*args, **kwargs)
        self.manifest = NULL_NODE_ID
        self.author = ''
        self.timestamp = ''
        self.utcoffset = ''
        self.files = []
        self.body = ''

    @classmethod
    def from_chunk(cls, raw_chunk, delta_cs=None):
        this = super(Changeset, cls).from_chunk(raw_chunk, delta_cs)
        data = raw_chunk.patch.apply(delta_cs.raw_data if delta_cs else '')
        metadata, this.body = data.split('\n\n', 1)
        lines = metadata.splitlines()
        this.manifest, this.author, date = lines[:3]
        date = date.split(' ', 2)
        this.timestamp = date[0]
        this.utcoffset = date[1]
        if len(date) == 3:
            this.extra = date[2]
        this.files = lines[3:]
        return this

    files = TypedProperty(list)

    class ExtraData(dict):
        @classmethod
        def from_str(cls, s):
            return cls(i.split(':', 1) for i in s.split('\0') if i)

        @classmethod
        def from_obj(cls, obj):
            if obj is None:
                return None
            if isinstance(obj, dict):
                return cls(obj)
            return cls.from_str(obj)

        def __str__(self):
            return '\0'.join(':'.join(i) for i in sorted(self.iteritems()))

    extra = TypedProperty(ExtraData)

    def _data_iter(self):
        yield self.manifest
        yield '\n'
        yield self.author
        yield '\n'
        yield self.timestamp
        yield ' '
        yield self.utcoffset
        if self.extra is not None:
            yield ' '
            yield str(self.extra)
        if self.files:
            yield '\n'
            yield '\n'.join(sorted(self.files))
        yield '\n\n'
        yield self.body

    @property
    def changeset(self):
        return self.node

    @changeset.setter
    def changeset(self, value):
        assert value in (self.node, NULL_NODE_ID)

    class ExtraProperty(object):
        def __init__(self, name):
            self._name = name

        def __get__(self, obj, type=None):
            if obj.extra is None:
                return None
            return obj.extra.get(self._name)

        def __set__(self, obj, value):
            if not value:
                if obj.extra:
                    try:
                        del obj.extra[self._name]
                    except KeyError:
                        pass
                if not obj.extra:
                    obj.extra = None
            else:
                if obj.extra is None:
                    obj.extra = {}
                obj.extra[self._name] = value

    branch = ExtraProperty('branch')
    committer = ExtraProperty('committer')
    close = ExtraProperty('close')
