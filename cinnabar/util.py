import logging
import os
import sys
import traceback
from collections import OrderedDict
from weakref import WeakKeyDictionary

from cinnabar.exceptions import Abort


class Formatter(logging.Formatter):
    def format(self, record):
        try:
            if hasattr(record, 'message'):
                record.message = record.message.replace('\n', '\0')
            else:
                record.msg = record.msg.replace('\n', '\0')
        except Exception:
            pass
        return super(Formatter, self).format(record)


class PipeHandler(logging.StreamHandler):
    def flush(self):
        try:
            super(PipeHandler, self).flush()
        except BrokenPipeError:
            # setStream calls flush, so if we error from there, we're doomed.
            # in other cases, we've already lost whatever was not flushed
            # anyways.
            pass

    def emit(self, record):
        try:
            super(PipeHandler, self).emit(record)
        except BrokenPipeError:
            self.setStream(sys.stderr)
            super(PipeHandler, self).emit(record)


def init_logging():
    from cinnabar.git import Git
    logger = logging.getLogger()
    fd = int(os.environ["GIT_CINNABAR_LOG_FD"])
    if sys.platform == 'win32':
        import msvcrt
        fd = msvcrt.open_osfhandle(fd, os.O_WRONLY)
    handler = PipeHandler(os.fdopen(fd, 'w'))
    handler.setFormatter(Formatter("%(levelname)s %(name)s %(message)s"))
    logger.addHandler(handler)
    log_conf = Git.config('cinnabar.log') or b''
    for assignment in log_conf.split(b','):
        try:
            assignment, _, path = assignment.partition(b'>')
            # path is handled by the rust end.
            name, _, value = assignment.partition(b':')
            name = name.decode('ascii')
            if name == '*':
                name = ''
            if value:
                logger = logging.getLogger(name)
                logger.setLevel(
                    max(logging.DEBUG, logging.FATAL - int(value) * 10))
        except Exception:
            pass


class ConfigSetFunc(object):
    def __init__(self, key, values, extra_values=(), default=''):
        self._config = None
        self._key = key
        self._values = values
        self._extra_values = extra_values
        self._default = default.encode('ascii')

    def __call__(self, name):
        if self._config is None:
            from cinnabar.git import Git
            config = Git.config(self._key) or self._default
            if config:
                config = config.decode('ascii').split(',')
            self._config = set()
            for c in config:
                if c in ('true', 'all'):
                    self._config |= set(self._values)
                elif c.startswith('-'):
                    c = c[1:]
                    try:
                        self._config.remove(c.decode('ascii'))
                    except KeyError:
                        logging.getLogger('config').warn(
                            '%s: %s is not one of (%s)',
                            self._key, c, ', '.join(self._config))
                elif c in self._values or c in self._extra_values:
                    self._config.add(c)
                else:
                    logging.getLogger('config').warn(
                        '%s: %s is not one of (%s)',
                        self._key, c, ', '.join(self._values))
        return name in self._config


check_enabled = ConfigSetFunc(
    'cinnabar.check',
    ('nodeid', 'manifests', 'helper'),
    ('bundle', 'files', 'time', 'traceback', 'no-bundle2', 'cinnabarclone',
     'clonebundles', 'no-version-check', 'unbundler'),
)

experiment = ConfigSetFunc(
    'cinnabar.experiments',
    ('merge',),
    (),
)


class IOLogger(object):
    def __init__(self, logger, reader, writer=None, prefix=''):
        self._reader = reader
        self._writer = writer or reader
        self._logger = logger
        self._prefix = (prefix + ' ') if prefix else ''

    def read(self, length=None, level=logging.INFO):
        if length is None:
            ret = self._reader.read()
        else:
            ret = self._reader.read(length)
        if not isinstance(self._reader, IOLogger):
            self._logger.log(level, '%s<= %r', self._prefix, ret)
        return ret

    def readline(self, level=logging.INFO):
        ret = self._reader.readline()
        if not isinstance(self._reader, IOLogger):
            self._logger.log(level, '%s<= %r', self._prefix, ret)
        return ret

    def write(self, data, level=logging.INFO):
        if not isinstance(self._writer, IOLogger):
            self._logger.log(level, '%s=> %r', self._prefix, data)
        return self._writer.write(data)

    def flush(self):
        self._writer.flush()

    def close(self):
        self._writer.close()

    def __iter__(self):
        while self._reader:
            line = self.readline()
            if not line:
                break
            yield line


class OrderedDefaultDict(OrderedDict):
    def __init__(self, default_factory, *args, **kwargs):
        OrderedDict.__init__(self, *args, **kwargs)
        self._default_factory = default_factory

    def __missing__(self, key):
        value = self[key] = self._default_factory()
        return value


def sorted_merge(iter_a, iter_b, key=lambda i: i[0], non_key=lambda i: i[1:]):
    iter_a = iter(iter_a)
    iter_b = iter(iter_b)
    item_a = next(iter_a, None)
    item_b = next(iter_b, None)
    while item_a is not None or item_b is not None:
        while item_a and (item_b and key(item_a) < key(item_b) or
                          item_b is None):
            yield key(item_a), non_key(item_a), ()
            item_a = next(iter_a, None)
        while item_b and (item_a and key(item_b) < key(item_a) or
                          item_a is None):
            yield key(item_b), (), non_key(item_b)
            item_b = next(iter_b, None)
        if item_a is None or item_b is None:
            continue
        key_a = key(item_a)
        if key_a == key(item_b):
            yield key_a, non_key(item_a), non_key(item_b)
            item_a = next(iter_a, None)
            item_b = next(iter_b, None)


class TypedProperty(object):
    def __init__(self, cls):
        self.cls = cls
        self.values = WeakKeyDictionary()

    def __get__(self, obj, cls=None):
        return self.values.get(obj)

    def __set__(self, obj, value):
        # If the class has a "from_obj" static or class method, use it.
        # Otherwise, just use cls(value)
        self.values[obj] = getattr(self.cls, 'from_obj', self.cls)(value)


def run(func, args):
    init_logging()

    try:
        retcode = func(args)
    except Abort as e:
        # These exceptions are normal abort and require no traceback
        retcode = 1
        logging.error(str(e))
    except Exception as e:
        # Catch all exceptions and provide a nice message
        retcode = 70  # Internal software error
        message = getattr(e, 'message', None) or getattr(e, 'reason', None)
        message = message or ', '.join(
            os.fsdecode(a) if isinstance(a, bytes) else str(a)
            for a in getattr(e, 'args', []))
        message = message or str(e)
        if check_enabled('traceback') or not message:
            traceback.print_exc()
        else:
            logging.error(os.fsdecode(message))

            logging.getLogger('stderr').error(
                'Run the command again with '
                '`git -c cinnabar.check=traceback <command>` to see the '
                'full traceback.')
    sys.exit(retcode)


def environ(k=None):
    if os.supports_bytes_environ:
        if k is None:
            return os.environb
        return os.environb.get(k)

    if k is None:
        return {
            os.fsencode(k): os.fsencode(v)
            for k, v in os.environ.items()
        }
    v = os.environ.get(os.fsdecode(k))
    if v is None:
        return None
    return os.fsencode(v)
