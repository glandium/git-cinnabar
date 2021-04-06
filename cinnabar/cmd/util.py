from __future__ import absolute_import, print_function, unicode_literals
import argparse
import os
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
    def helper_subcommand(name, help):
        subparser = CLI.subparsers.add_parser(name, help=help, add_help=False)
        subparser.add_argument('args', nargs=argparse.REMAINDER)

        def func(args):
            from cinnabar.helper import GitHgHelper
            import subprocess

            command, env = GitHgHelper._helper_command()
            if len(command) == 1:
                executable = command[0]
                command[0] = 'git-cinnabar'
            else:
                executable = None
            environ = dict(os.environ)
            environ.update(env)
            cmd = command + [args.command] + args.args
            retcode = subprocess.call(cmd, executable=executable,
                                      env=environ)
            if retcode == 128:
                GitHgHelper._helper_error('outdated')
            return retcode

        def parse_known_args(args=None, namespace=None):
            if namespace is None:
                namespace = argparse.Namespace()
            setattr(namespace, 'args', args)
            setattr(namespace, 'callback', func)
            return namespace, []

        setattr(subparser, 'parse_known_args', parse_known_args)

    @staticmethod
    def prepare(argv):
        CLI.parser.add_argument('--version', action=Version)

        args, leftovers = CLI.parser.parse_known_args(argv)

        if not hasattr(args, 'callback'):
            CLI.parser.print_help()
            CLI.parser.exit()

        if hasattr(args.callback, 'cli_remainder'):
            args = argparse.Namespace(**{
                'callback': args.callback,
                args.callback.cli_remainder: leftovers,
            })
        else:
            args = CLI.parser.parse_args(argv)
        return (args.callback, args)


class Version(argparse.Action):
    def __init__(self, option_strings, dest=argparse.SUPPRESS,
                 default=argparse.SUPPRESS,
                 help="show program's version number and exit"):
        super(Version, self).__init__(
            option_strings=option_strings, dest=dest, default=default,
            nargs=0, help=help)

    @staticmethod
    def helper_version():
        from cinnabar.helper import GitHgHelper
        try:
            with GitHgHelper.query(b'revision') as out:
                return out.read(40).decode('ascii')
        except Exception:
            return 'unknown'

    def __call__(self, parser, namespace, values, option_string=None):
        print(VERSION)
        version = self.helper_version()
        print('helper-hash:', version)

        parser.exit()
