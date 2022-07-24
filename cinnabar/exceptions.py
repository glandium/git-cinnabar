class Abort(Exception):
    """Raised if a command needs to print an error and exit."""


class HelperClosedError(RuntimeError):
    """Running a query with a closed helper."""


class SilentlyAbort(Abort):
    """Native side expected to print an error."""
