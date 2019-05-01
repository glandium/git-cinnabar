import argparse
import os
import sys
from cinnabar.helper import helper_hash, tree_hash
from cinnabar import VERSION


class CLI(object):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title='subcommands', dest='command')

    @staticmethod
    def argument(*args, **kwargs):
        def decorator(func):
            if not hasattr(func, 'cli_arguments'):
                func.cli_arguments = []
            func.cli_arguments.append((args, kwargs))
            return func
        return decorator

    @staticmethod
    def subcommand(func):
        subparser = CLI.subparsers.add_parser(func.__name__, help=func.__doc__)
        if hasattr(func, 'cli_arguments'):
            # Because argparse.REMAINDER can't be used as first argument
            # without making flags emit a "unrecognized argument" error,
            # treat that specially.
            if len(func.cli_arguments) == 1:
                args, kwargs = func.cli_arguments[0]
                if kwargs.get('nargs') == argparse.REMAINDER:
                    func.cli_remainder = args[0]
                    func.cli_arguments = ()
            for args, kwargs in reversed(func.cli_arguments):
                subparser.add_argument(*args, **kwargs)
            del func.cli_arguments
        subparser.set_defaults(callback=func)

    @staticmethod
    def run(argv):
        CLI.parser.add_argument('--version', action=Version)

        args, leftovers = CLI.parser.parse_known_args(argv)
        if hasattr(args.callback, 'cli_remainder'):
            args = argparse.Namespace(**{
                'callback': args.callback,
                args.callback.cli_remainder: leftovers,
            })
        return args.callback(args)


def iter_modules_in_path(path):
    base = os.path.abspath(os.path.normcase(path)) + os.sep
    for name, module in sys.modules.items():
        if not hasattr(module, '__file__'):
            continue

        path = module.__file__

        if path.endswith('.pyc'):
            path = path[:-1]
        path = os.path.abspath(os.path.normcase(path))

        if path.startswith(base):
            yield os.path.relpath(path, base)


class Version(argparse.Action):
    def __init__(self, option_strings, dest=argparse.SUPPRESS,
                 default=argparse.SUPPRESS,
                 help="show program's version number and exit"):
        super(Version, self).__init__(
            option_strings=option_strings, dest=dest, default=default,
            nargs='?', choices=('cinnabar', 'module', 'helper'),
            help=help)

    @staticmethod
    def cinnabar_version():
        return VERSION

    @staticmethod
    def module_version():
        # Import the remote_helper module, that is not imported by
        # git-cinnabar
        import cinnabar.remote_helper
        # Import the bdiff module, that is only imported if mercurial is
        # not installed
        import cinnabar.bdiff
        cinnabar_path = os.path.dirname(cinnabar.__file__)
        return tree_hash(iter_modules_in_path(cinnabar_path), cinnabar_path)

    @staticmethod
    def helper_version():
        from cinnabar.helper import GitHgHelper
        try:
            with GitHgHelper.query('revision') as out:
                version = out.read(40)
        except Exception:
            version = 'unknown'

        sha1 = helper_hash() or 'unknown'
        return version, sha1

    def __call__(self, parser, namespace, values, option_string=None):
        if values == 'cinnabar' or not values:
            print self.cinnabar_version()
        if values == 'module' or not values:
            sha1 = self.module_version()
            if not values:
                print 'module-hash:', sha1
            else:
                print sha1
        if values == 'helper' or not values:
            version, sha1 = self.helper_version()
            if version != sha1:
                sha1 = '%s/%s' % (version, sha1)
            if not values:
                print 'helper-hash:', sha1
            else:
                print sha1

        parser.exit()
