import argparse
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
        CLI.parser.add_argument('--version', action='version', version=VERSION)

        args, leftovers = CLI.parser.parse_known_args(argv)
        if hasattr(args.callback, 'cli_remainder'):
            args = argparse.Namespace(**{
                'callback': args.callback,
                args.callback.cli_remainder: leftovers,
            })
        return args.callback(args)
