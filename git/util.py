class LazyString(object):
    def __init__(self, fn):
        self._fn = fn

    def __str__(self):
        return self._fn()


def one(l):
    l = list(l)
    if l:
        assert len(l) == 1
        return l[0]
    return None
