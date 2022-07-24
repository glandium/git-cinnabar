import logging
import os
import subprocess
from cinnabar.util import environ

NULL_NODE_ID = b'0' * 40
# An empty git tree has a fixed sha1 which is that of "tree 0\0"
EMPTY_TREE = b'4b825dc642cb6eb9a060e54bf8d69288fbee4904'
# An empty git blob has a fixed sha1 which is that of "blob 0\0"
EMPTY_BLOB = b'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391'


class InvalidConfig(Exception):
    pass


class Git(object):
    _config = None

    @classmethod
    def config(self, name, remote=None, values={}, multiple=False):
        assert not (values and multiple)
        if self._config is None:
            data = subprocess.check_output(['git', 'config', '-l', '-z'])
            self._config = {}
            for l in data.split(b'\0'):
                if l:
                    k, v = l.split(b'\n', 1)
                    if k in self._config:
                        self._config[k] += b'\0' + v
                    else:
                        self._config[k] = v

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
