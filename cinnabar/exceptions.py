from __future__ import unicode_literals


class Abort(Exception):
    """Raised if a command needs to print an error and exit."""


class HelperClosedError(RuntimeError):
    """Running a query with a closed helper."""


class HelperFailedError(RuntimeError):
    """Helper returned an error code."""


class NothingToGraftException(Exception):
    """Not found any tree to graft."""


class AmbiguousGraftAbort(Abort):
    """Cannot graft the changeset."""
