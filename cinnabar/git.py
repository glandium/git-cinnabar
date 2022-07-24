import logging
import os
import time
from cinnabar.util import (
    environ,
    Process,
)
from itertools import chain

NULL_NODE_ID = b'0' * 40
# An empty git tree has a fixed sha1 which is that of "tree 0\0"
EMPTY_TREE = b'4b825dc642cb6eb9a060e54bf8d69288fbee4904'
# An empty git blob has a fixed sha1 which is that of "blob 0\0"
EMPTY_BLOB = b'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391'


class InvalidConfig(Exception):
    pass


class GitProcess(Process):
    def __init__(self, *args, **kwargs):
        config = kwargs.pop('config', {})

        command = ['git']
        command += chain(*(['-c', '%s=%s' % (n, v)]
                           for n, v in config.items()))
        command += args

        kwargs.setdefault('logger', args[0])
        super(GitProcess, self).__init__(*command, **kwargs)


class Git(object):
    _notes_depth = {}
    _config = None

    @classmethod
    def iter(self, *args, **kwargs):
        start = time.time()

        if args[0] == 'config':
            self._config = None

        proc = GitProcess(*args, **kwargs)
        try:
            for line in proc.stdout or ():
                line = line.rstrip(b'\n')
                yield line

        finally:
            proc.wait()
            logging.getLogger(args[0]).info('[%d] wall time: %.3fs',
                                            proc.pid, time.time() - start)

    @classmethod
    def run(self, *args, **kwargs):
        stdout = kwargs.pop('stdout', None)
        return tuple(self.iter(*args, stdout=stdout, **kwargs))

    @classmethod
    def config(self, name, remote=None, values={}, multiple=False):
        assert not (values and multiple)
        if self._config is None:
            proc = GitProcess('config', '-l', '-z')
            data = proc.stdout.read()
            proc.wait()
            self._config = {}
            for l in data.split(b'\0'):
                if l:
                    k, v = l.split(b'\n', 1)
                    if k in self._config:
                        self._config[k] += b'\0' + v
                    else:
                        self._config[k] = v
            if self._config.pop(b'cinnabar.fsck', None):
                # Git.run('config') will reset self._config ; avoid that.
                config = self._config
                # We used to set cinnabar.fsck globally, then locally.
                # Remove both.
                Git.run('config', '--global', '--unset', 'cinnabar.fsck')
                Git.run('config', '--local', '--unset', 'cinnabar.fsck')
                self._config = config

        var = name.encode('ascii')
        value = None
        if name.startswith('cinnabar.'):
            var = ('GIT_%s' % name.replace('.', '_').upper()).encode('ascii')
            value = environ(var)
            if value is None and remote:
                var = b'remote.%s.%s' % (
                    remote, name.replace('.', '-').encode('ascii'))
                value = self._config.get(var.lower())
        if value is None:
            var = name.encode('ascii')
            value = self._config.get(var.lower())
        if value:
            value = value.split(b'\0')
            if not multiple:
                value = value[-1]
        logging.getLogger('config').info('%s = %r', var, value)
        if values:
            if value in values:
                if isinstance(values, dict):
                    value = values[value]
            else:
                values = ', '.join(sorted('"%s"' % v.decode('ascii')
                                          for v in values
                                          if v is not None))
                if value is None:
                    raise InvalidConfig(
                        '%s must be set to one of %s' % (
                            var.decode('ascii'), values))
                else:
                    raise InvalidConfig(
                        'Invalid value for %s: "%s". Valid values: %s' % (
                            var.decode('ascii'), os.fsdecode(value), values))
        return value
