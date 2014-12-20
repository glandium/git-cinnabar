import logging


def next(iter):
    try:
        return iter.next()
    except StopIteration:
        return None


class IOLogger(object):
    def __init__(self, logger, reader, writer=None, prefix=''):
        self._reader = reader
        self._writer = writer or reader
        self._logger = logger
        self._prefix = (prefix + ' ') if prefix else ''

    def read(self, length=0, level=logging.INFO):
        ret = self._reader.read(length)
        self._logger.log(level, LazyString(lambda: '%s<= %s'
                                           % (self._prefix, repr(ret))))
        return ret

    def readline(self, level=logging.INFO):
        ret = self._reader.readline()
        self._logger.log(level, LazyString(lambda: '%s<= %s'
                                           % (self._prefix, repr(ret))))
        return ret

    def write(self, data, level=logging.INFO):
        self._logger.log(level, LazyString(lambda: '%s=> %s'
                                           % (self._prefix, repr(data))))
        return self._writer.write(data)

    def flush(self):
        self._writer.flush()


class LazyString(object):
    def __init__(self, obj):
        self._obj = obj

    def __str__(self):
        if callable(self._obj):
            return self._obj()
        return self._obj


def one(l):
    l = list(l)
    if l:
        assert len(l) == 1
        return l[0]
    return None
