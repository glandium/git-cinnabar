import logging
import os
import subprocess
import sys
import time
import traceback
from collections import (
    deque,
    Iterable,
    OrderedDict,
)
from difflib import (
    Match,
    SequenceMatcher,
)
from functools import wraps
from itertools import (
    chain,
    izip,
)
from Queue import (
    Empty,
    Queue,
)
from threading import Thread
from types import StringType
from weakref import WeakKeyDictionary

from .exceptions import Abort


class StreamHandler(logging.StreamHandler):
    def __init__(self):
        super(StreamHandler, self).__init__()
        self._start_time = time.time()

    def emit(self, record):
        record.timestamp = record.created - self._start_time
        super(StreamHandler, self).emit(record)


class Formatter(logging.Formatter):
    def __init__(self):
        super(Formatter, self).__init__(
            '\r%(timestamp).3f %(levelname)s [%(name)s] %(message)s')
        self._root_formatter = logging.Formatter('\r%(levelname)s %(message)s')

    def format(self, record):
        if record.name == 'root':
            return self._root_formatter.format(record)
        return super(Formatter, self).format(record)


def init_logging():
    # Initialize logging from the GIT_CINNABAR_LOG environment variable
    # or the cinnabar.log configuration, the former taking precedence.
    # Still read the configuration to force the git config cache being
    # filled before logging is setup, so that the output of
    # `git config -l` is never logged.
    from .git import Git
    log_conf = Git.config('cinnabar.log')
    if not log_conf:
        return
    for assignment in log_conf.split(','):
        try:
            name, value = assignment.split(':', 1)
            value = int(value)
            if name == '*':
                name = ''
            logging.getLogger(name).setLevel(
                max(logging.DEBUG, logging.FATAL - value * 10))
        except Exception:
            pass

    logger = logging.getLogger()
    handler = StreamHandler()
    handler.setFormatter(Formatter())
    logger.addHandler(handler)


class ConfigSetFunc(object):
    def __init__(self, key, values, extra_values=()):
        self._config = None
        self._key = key
        self._values = values
        self._extra_values = extra_values

    def __call__(self, name):
        if self._config is None:
            from .git import Git
            config = Git.config(self._key) or ''
            if config:
                config = config.split(',')
            self._config = set()
            for c in config:
                if c in ('true', 'all'):
                    self._config |= set(self._values)
                elif c.startswith('-'):
                    c = c[1:]
                    try:
                        self._config.remove(c)
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
    ('bundle', 'files', 'memory', 'time', 'traceback', 'no-mercurial',
     'no-bundle2'),
)

experiment = ConfigSetFunc(
    'cinnabar.experiments',
    ('wire', 'merge', 'store-manifest', 'git-clone'),
)


progress = True


try:
    if check_enabled('no-mercurial'):
        raise ImportError('Do not use mercurial')
    from mercurial.mdiff import textdiff  # noqa: F401
except ImportError:
    from .bdiff import bdiff as textdiff  # noqa: F401


def progress_iter(fmt, iter):
    return progress_enum(fmt, enumerate(iter, start=1))


def progress_enum(fmt, enum_iter):
    count = 0
    t0 = start = time.time()
    try:
        for count, item in enum_iter:
            if progress:
                t1 = time.time()
                if t1 - t0 > 0.1:
                    if not isinstance(count, tuple):
                        count = (count,)
                    sys.stderr.write('\r' + fmt.format(*count))
                    if check_enabled('time'):
                        sys.stderr.write(' in %.1fs' % (t1 - start))
                    sys.stderr.flush()
                    t0 = t1
            yield item
    finally:
        if progress and count:
            if not isinstance(count, tuple):
                count = (count,)
            timed = ''
            if check_enabled('time'):
                timed = ' in %.1fs' % (time.time() - start)
            sys.stderr.write('\r' + fmt.format(*count) + timed + '\n')
            sys.stderr.flush()


class IOLogger(object):
    def __init__(self, logger, reader, writer=None, prefix=''):
        self._reader = reader
        self._writer = writer or reader
        self._logger = logger
        self._prefix = (prefix + ' ') if prefix else ''

    def read(self, length=0, level=logging.INFO):
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

    def __iter__(self):
        while self._reader:
            line = self.readline()
            if not line:
                break
            yield line


def one(iterable):
    lst = list(iterable)
    if lst:
        assert len(lst) == 1
        return lst[0]
    return None


class OrderedDefaultDict(OrderedDict):
    def __init__(self, default_factory, *args, **kwargs):
        OrderedDict.__init__(self, *args, **kwargs)
        self._default_factory = default_factory

    def __missing__(self, key):
        value = self[key] = self._default_factory()
        return value


class VersionedDict(object):
    def __init__(self, content=None, **kwargs):
        if content:
            if kwargs:
                self._previous = VersionedDict(content)
                for k, v in kwargs.iteritems():
                    self._previous[k] = v
            elif isinstance(content, (VersionedDict, dict)):
                self._previous = content
            else:
                self._previous = dict(content)
        else:
            self._previous = dict(**kwargs)
        self._dict = {}
        self._deleted = set()

    def update(self, content=None, **kwargs):
        if content:
            if isinstance(content, (VersionedDict, dict)):
                content = content.iteritems()
            for k, v in content:
                self[k] = v
        for k, v in kwargs.iteritems():
            self[k] = v

    def __getitem__(self, key):
        if key in self._dict:
            return self._dict[key]
        return self._previous[key]

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key):
        if key in self._deleted:
            return False
        if key in self._dict:
            return True
        return key in self._previous

    def __delitem__(self, key):
        self._deleted.add(key)
        if key in self._dict:
            del self._dict[key]
        elif key not in self._previous:
            raise KeyError(key)

    def __setitem__(self, key, value):
        if key in self._deleted:
            self._deleted.remove(key)
        self._dict[key] = value

    def __len__(self):
        return len(self._dict) + sum(1 for k in self._previous
                                     if k not in self._deleted and
                                     k not in self._dict)

    def keys(self):
        if self._previous:
            return list(self)
        return self._dict.keys()

    def values(self):
        if self._previous:
            return list(chain(
                self._dict.values(),
                (v for k, v in self._previous.iteritems()
                 if k not in self._deleted and k not in self._dict)))
        return self._dict.values()

    def __iter__(self):
        if self._previous:
            return chain(self._dict,
                         (k for k in self._previous
                          if k not in self._deleted and k not in self._dict))
        return iter(self._dict)

    def iteritems(self):
        if self._previous:
            return chain(
                self._dict.iteritems(),
                ((k, v) for k, v in self._previous.iteritems()
                 if k not in self._deleted and k not in self._dict))
        return self._dict.iteritems()

    CREATED = 1
    MODIFIED = 2
    REMOVED = 3

    def iterchanges(self):
        for k, v in self._dict.iteritems():
            if k in self._previous:
                if self._previous[k] == v:
                    continue
                status = self.MODIFIED
            else:
                status = self.CREATED
            yield status, k, v
        for k in self._deleted:
            if k in self._previous:
                yield self.REMOVED, k, self._previous[k]

    def flattened(self):
        previous = self
        changes = []
        while isinstance(previous, VersionedDict):
            changes.append(previous.iterchanges())
            previous = previous._previous

        ret = VersionedDict(previous)

        # This can probably be optimized, but it shouldn't matter much that
        # it's not.
        for c in reversed(changes):
            for status, k, v in c:
                if status == self.REMOVED:
                    del ret[k]
                else:
                    ret[k] = v
        return ret


def _iter_diff_blocks(a, b):
    m = SequenceMatcher(a=a, b=b, autojunk=False).get_matching_blocks()
    for start, end in izip(chain((Match(0, 0, 0),), m), m):
        if start.a + start.size != end.a or start.b + start.size != end.b:
            yield start.a + start.size, end.a, start.b + start.size, end.b


def byte_diff(a, b):
    '''Given two strings, returns the diff between them, at the byte level.

    Yields start offset in a, end offset in a and replacement string for
    each difference. Far from optimal results, but works well enough.'''
    a = tuple(a.splitlines(True))
    b = tuple(b.splitlines(True))
    offset = 0
    last = 0
    for start_a, end_a, start_b, end_b in _iter_diff_blocks(a, b):
        a2 = ''.join(a[start_a:end_a])
        b2 = ''.join(b[start_b:end_b])
        offset += sum(len(i) for i in a[last:start_a])
        last = start_a
        for start2_a, end2_a, start2_b, end2_b in _iter_diff_blocks(a2, b2):
            yield offset + start2_a, offset + end2_a, b2[start2_b:end2_b]


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


class lrucache(object):
    class node(object):
        __slots__ = ('next', 'prev', 'key', 'value')

        def __init__(self):
            self.next = self.prev = None

        def insert(self, after):
            if self.next and self.prev:
                self.next.prev = self.prev
                self.prev.next = self.next
            self.next = after.next
            self.prev = after
            after.next = self
            self.next.prev = self

        def detach(self):
            assert self.next
            assert self.prev
            self.prev.next = self.next
            self.next.prev = self.prev
            self.next = self.prev = None

    def __init__(self, size):
        self._size = max(size, 2)
        self._cache = {}
        self._top = self.node()
        self._top.next = self._top
        self._top.prev = self._top

    def __call__(self, func):
        @wraps(func)
        def wrapper(*args):
            try:
                return self[args]
            except KeyError:
                result = func(*args)
                self[args] = result
                return result
        wrapper.invalidate = self.invalidate
        return wrapper

    def invalidate(self, *args):
        if len(args) == 0:
            keys = list(self._cache)
            for k in keys:
                del self[k]
            return
        try:
            del self[args]
        except KeyError:
            pass

    def __getitem__(self, key):
        node = self._cache[key]
        node.insert(self._top)
        return node.value

    def __setitem__(self, key, value):
        if key in self._cache:
            node = self._cache[key]
        else:
            node = self.node()
            node.key = key

        node.value = value
        node.insert(self._top)

        self._cache[key] = node
        while len(self._cache) > self._size:
            node = self._top.prev
            node.detach()
            del self._cache[node.key]

    def __delitem__(self, key):
        node = self._cache.pop(key)
        node.detach()

    def __len__(self):
        node = self._top.next
        count = 0
        while node is not self._top:
            count += 1
            node = node.next
        assert count == len(self._cache)
        return len(self._cache)


# The following class was copied from mercurial.
#  Copyright 2005 K. Thananchayan <thananck@yahoo.com>
#  Copyright 2005-2007 Matt Mackall <mpm@selenic.com>
#  Copyright 2006 Vadim Gelfer <vadim.gelfer@gmail.com>
class chunkbuffer(object):
    """Allow arbitrary sized chunks of data to be efficiently read from an
    iterator over chunks of arbitrary size."""

    def __init__(self, in_iter):
        """in_iter is the iterator that's iterating over the input chunks."""
        def splitbig(chunks):
            for chunk in chunks:
                if len(chunk) > 2 ** 20:
                    pos = 0
                    while pos < len(chunk):
                        end = pos + 2 ** 18
                        yield chunk[pos:end]
                        pos = end
                else:
                    yield chunk
        self.iter = splitbig(in_iter)
        self._queue = deque()
        self._chunkoffset = 0

    def read(self, l=None):
        """Read L bytes of data from the iterator of chunks of data.
        Returns less than L bytes if the iterator runs dry.

        If size parameter is omitted, read everything"""
        if l is None:
            return ''.join(self.iter)

        left = l
        buf = []
        queue = self._queue
        while left > 0:
            # refill the queue
            if not queue:
                target = 2 ** 18
                for chunk in self.iter:
                    queue.append(chunk)
                    target -= len(chunk)
                    if target <= 0:
                        break
                if not queue:
                    break

            # The easy way to do this would be to queue.popleft(), modify the
            # chunk (if necessary), then queue.appendleft(). However, for cases
            # where we read partial chunk content, this incurs 2 dequeue
            # mutations and creates a new str for the remaining chunk in the
            # queue. Our code below avoids this overhead.

            chunk = queue[0]
            chunkl = len(chunk)
            offset = self._chunkoffset

            # Use full chunk.
            if offset == 0 and left >= chunkl:
                left -= chunkl
                queue.popleft()
                buf.append(chunk)
                # self._chunkoffset remains at 0.
                continue

            chunkremaining = chunkl - offset

            # Use all of unconsumed part of chunk.
            if left >= chunkremaining:
                left -= chunkremaining
                queue.popleft()
                # offset == 0 is enabled by block above, so this won't merely
                # copy via ``chunk[0:]``.
                buf.append(chunk[offset:])
                self._chunkoffset = 0

            # Partial chunk needed.
            else:
                buf.append(chunk[offset:offset + left])
                self._chunkoffset += left
                left -= chunkremaining

        return ''.join(buf)


class Process(object):
    def __init__(self, *args, **kwargs):
        stdin = kwargs.pop('stdin', None)
        stdout = kwargs.pop('stdout', subprocess.PIPE)
        stderr = kwargs.pop('stderr', None)
        logger = kwargs.pop('logger', args[0])
        env = kwargs.pop('env', {})
        cwd = kwargs.pop('cwd', None)
        assert not kwargs
        if isinstance(stdin, (StringType, Iterable)):
            proc_stdin = subprocess.PIPE
        else:
            proc_stdin = stdin

        full_env = VersionedDict(os.environ)
        if env:
            full_env.update(env)

        self._proc = self._popen(args, stdin=proc_stdin, stdout=stdout,
                                 stderr=stderr, env=full_env, cwd=cwd)

        logger = logging.getLogger(logger)
        if logger.isEnabledFor(logging.INFO):
            self._stdin = IOLogger(logger, self._proc.stdout, self._proc.stdin,
                                   prefix='[%d]' % self.pid)
        else:
            self._stdin = self._proc.stdin

        if logger.isEnabledFor(logging.DEBUG):
            self._stdout = self._stdin
        else:
            self._stdout = self._proc.stdout

        if proc_stdin == subprocess.PIPE:
            if isinstance(stdin, StringType):
                self._stdin.write(stdin)
            elif isinstance(stdin, Iterable):
                for line in stdin:
                    self._stdin.write('%s\n' % line)
            if proc_stdin != stdin:
                self._proc.stdin.close()

    def _env_strings(self, env):
        for k, v in sorted((k, v) for s, k, v in env.iterchanges()
                           if s != env.REMOVED):
            yield '%s=%s' % (k, v)

    def _popen(self, cmd, env, **kwargs):
        assert isinstance(env, VersionedDict)
        proc = subprocess.Popen(cmd, env=env, **kwargs)
        logger = logging.getLogger('process')
        if logger.isEnabledFor(logging.INFO):
            logger.info('[%d] %s', proc.pid,
                        ' '.join(chain(self._env_strings(env), cmd)))
        return proc

    def wait(self):
        for fh in (self._proc.stdin, self._proc.stdout, self._proc.stderr):
            if fh:
                fh.close()
        pid = self._proc.pid
        retcode = self._proc.wait()
        logger = logging.getLogger('process')
        if logger.isEnabledFor(logging.INFO):
            logger.info('[%d] Exited with code %d', pid, retcode)
        return retcode

    @property
    def pid(self):
        return self._proc.pid

    @property
    def stdin(self):
        return self._stdin

    @property
    def stdout(self):
        return self._stdout

    @property
    def stderr(self):
        return self._proc.stderr


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


class MemoryReporter(Thread):
    def __init__(self):
        super(MemoryReporter, self).__init__()
        self._queue = Queue(1)
        self._logger = logging.getLogger('memory')
        self._logger.setLevel(logging.INFO)
        self.start()

    def _report(self, proc):
        self._logger.info(
            '[%s(%d)] %r', proc.name(), proc.pid, proc.memory_info())

    def run(self):
        import psutil
        proc = psutil.Process()
        while True:
            try:
                self._queue.get(True, 1)
                break
            except Empty:
                pass
            except Exception:
                break
            finally:
                children = proc.children(recursive=True)
                self._report(proc)
                for p in children:
                    self._report(p)

    def shutdown(self):
        self._queue.put(None)
        self.join()


def run(func):
    init_logging()
    if check_enabled('memory'):
        reporter = MemoryReporter()

    try:
        retcode = func(sys.argv[1:])
    except Abort as e:
        # These exceptions are normal abort and require no traceback
        retcode = 1
        logging.error(e.message)
    except Exception as e:
        # Catch all exceptions and provide a nice message
        retcode = 70  # Internal software error
        if check_enabled('traceback') or not getattr(e, 'message', None):
            traceback.print_exc()
        else:
            logging.error(e.message)

            sys.stderr.write(
                'Run the command again with '
                '`git -c cinnabar.check=traceback <command>` to see the '
                'full traceback.\n')
    finally:
        if check_enabled('memory'):
            reporter.shutdown()
    sys.exit(retcode)
