from __future__ import division
import logging
import os
import posixpath
import time
from .util import (
    one,
    Process,
)
from itertools import chain

NULL_NODE_ID = '0' * 40
# An empty git tree has a fixed sha1 which is that of "tree 0\0"
EMPTY_TREE = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'
# An empty git blob has a fixed sha1 which is that of "blob 0\0"
EMPTY_BLOB = 'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391'


class InvalidConfig(Exception):
    pass


def split_ls_tree(line):
    mode, typ, remainder = line.split(' ', 2)
    sha1, path = remainder.split('\t', 1)
    return mode, typ, sha1, path


class GitProcess(Process):
    def __init__(self, *args, **kwargs):
        config = kwargs.pop('config', {})

        command = ['git']
        command += chain(*(['-c', '%s=%s' % (n, v)]
                           for n, v in config.iteritems()))
        command += args

        kwargs.setdefault('logger', args[0])
        super(GitProcess, self).__init__(*command, **kwargs)


class Git(object):
    _notes_depth = {}
    _config = None
    _replace = {}

    @classmethod
    def iter(self, *args, **kwargs):
        start = time.time()

        proc = GitProcess(*args, **kwargs)
        try:
            for line in proc.stdout or ():
                line = line.rstrip('\n')
                yield line

        finally:
            proc.wait()
            logging.getLogger(args[0]).info('[%d] wall time: %.3fs',
                                            proc.pid, time.time() - start)

    @classmethod
    def run(self, *args):
        return tuple(self.iter(*args, stdout=None))

    @classmethod
    def for_each_ref(self, *patterns):
        if not patterns:
            return
        # Ideally, this would not actually call for-each-ref if all refs
        # matching the given patterns are already known.
        for line in self.iter('for-each-ref', '--format',
                              '%(objectname) %(refname)', *patterns):
            yield line.split(' ', 1)

    @classmethod
    def resolve_ref(self, ref):
        return one(Git.iter('rev-parse', '--revs-only', ref))

    @classmethod
    def ls_tree(self, treeish, path='', recursive=False):
        from .helper import GitHgHelper
        assert not treeish.startswith('refs/')

        if path.endswith('/') or recursive or path == '':
            path = path.rstrip('/')
            for line in GitHgHelper.ls_tree('%s:%s' % (treeish, path),
                                            recursive):
                mode, typ, sha1, p = line
                if path:
                    yield mode, typ, sha1, posixpath.join(path, p)
                else:
                    yield mode, typ, sha1, p
        else:
            with GitHgHelper.query('ls', treeish, path) as stdout:
                line = stdout.readline()
                if not line.startswith('missing '):
                    yield split_ls_tree(line[:-1])

    @classmethod
    def update_ref(self, ref, newvalue):
        assert not newvalue.startswith('refs/')
        from .helper import GitHgHelper
        GitHgHelper.update_ref(ref, newvalue)

    @classmethod
    def delete_ref(self, ref):
        self.update_ref(ref, '0' * 40)

    @classmethod
    def config(self, name, remote=None, values={}, multiple=False):
        assert not (values and multiple)
        if self._config is None:
            proc = GitProcess('config', '-l', '-z')
            data = proc.stdout.read()
            proc.wait()
            self._config = {}
            for l in data.split('\0'):
                if l:
                    k, v = l.split('\n', 1)
                    if k in self._config:
                        self._config[k] += '\0' + v
                    else:
                        self._config[k] = v
        var = name
        value = None
        if name.startswith('cinnabar.'):
            var = 'GIT_%s' % name.replace('.', '_').upper()
            value = os.environ.get(var)
            if value is None and remote:
                var = 'remote.%s.%s' % (remote, name.replace('.', '-'))
                value = self._config.get(var.lower())
        elif name == 'fetch.prune' and remote:
            var = 'remote.%s.prune' % remote
            value = self._config.get(var.lower())
        if value is None:
            var = name
            value = self._config.get(var.lower())
        if value:
            value = value.split('\0')
            if not multiple:
                value = value[-1]
        logging.getLogger('config').info('%s = %r', var, value)
        if values:
            if value in values:
                if isinstance(values, dict):
                    value = values[value]
            else:
                values = ', '.join(repr(v) for v in sorted(values)
                                   if v is not None)
                if value is None:
                    raise InvalidConfig(
                        '%s must be set to one of %s' % (var, values))
                else:
                    raise InvalidConfig(
                        'Invalid value for %s: %s. Valid values: %s' % (
                            var, repr(value), values))
        return value
