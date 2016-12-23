import os
import sys
import argparse
import platform
import subprocess
import tempfile
import threading
import zipfile
import errno
from StringIO import StringIO
from cinnabar import VERSION
from cinnabar.cmd.util import (
    CLI,
    helper_hash,
)
from cinnabar.git import Git
from cinnabar.util import progress_enum


@CLI.subcommand
@CLI.argument('--url', action='store_true',
              help='only print the download url')
@CLI.argument('--dev', nargs='?', metavar='VARIANT',
              default=False,
              help='download the development helper')
@CLI.argument('--system', default=platform.system(),
              help=argparse.SUPPRESS)
@CLI.argument('--machine', default=platform.machine(),
              help=argparse.SUPPRESS)
@CLI.argument('-o', '--output', help=argparse.SUPPRESS)
@CLI.argument('--no-config', action='store_true',
              help=argparse.SUPPRESS)
@CLI.argument('--list', action='store_true',
              help=argparse.SUPPRESS)
def download(args):
    '''download a prebuilt helper'''

    helper = 'git-cinnabar-helper'
    system = args.system
    machine = args.machine
    if system == 'Darwin':
        system = 'macOS'
    elif system == 'Windows':
        helper += '.exe'

    available = (
        ('Linux', 'x86_64'),
        ('macOS', 'x86_64'),
        ('Windows', 'AMD64'),
        ('Windows', 'x86'),
    )

    if args.list:
        for system, machine in available:
            print "%s/%s" % (system, machine)
        return 0

    if (system, machine) not in available:
        print >>sys.stderr, 'No download available for %s/%s' % (system,
                                                                 machine)
        return 1

    if args.dev is False and VERSION.endswith('a'):
        args.dev = ''

    script_path = os.path.dirname(os.path.abspath(sys.argv[0]))

    if args.dev is not False:
        sha1 = helper_hash()
        if sha1 is None:
            print >>sys.stderr, (
                'Cannot find the right development helper for this '
                'version of git cinnabar.')
            return 1
        system_variant = system
        if args.dev:
            system_variant = '%s-%s' % (system, args.dev.lower())
        url = 'https://s3.amazonaws.com/git-cinnabar/artifacts/%s/%s/%s/%s' % (
            sha1, system_variant, machine, helper)
    else:
        if system in ('Windows', 'macOS'):
            ext = 'zip'
        else:
            ext = 'tar.xz'
        REPO_BASE = 'https://github.com/glandium'
        url = '%s/git-cinnabar/releases/download/%s/git-cinnabar.%s.%s.%s' % (
            REPO_BASE, VERSION, system.lower(), machine.lower(), ext)

    if args.url:
        print url
        return 0

    try:
        import requests
    except ImportError:
        print >>sys.stderr, (
            'Downloading the helper requires the `requests` python module.')
        return 1

    if args.output:
        d = os.path.dirname(args.output)
    else:
        d = script_path
        if not os.access(d, os.W_OK):
            d = os.path.join(os.path.expanduser('~'), '.git-cinnabar')
            try:
                os.makedirs(d)
            except:
                pass
            if not os.path.isdir(d):
                print >>sys.stderr, (
                    'Cannot write to either %s or %s.' % (d, script_path))
                return 1

    print 'Downloading from %s...' % url
    req = requests.get(url, stream=True)
    if req.status_code != 200:
        # Try again, just in case
        req = requests.get(url, stream=True)
    if req.status_code != 200:
        print >>sys.stderr, (
            'Download failed with status code %d\n' % req.status_code)
        print >>sys.stderr, 'Error body was:\n\n%s' % req.content
        return 1

    size = int(req.headers.get('Content-Length', '0'))

    def progress(iter, size=0):
        def _progress(iter, size):
            read = 0
            for chunk in iter:
                read += len(chunk)
                if size:
                    yield read * 100 / size, chunk
                else:
                    yield read, chunk

        fmt = ' %d%%' if size else ' %d bytes'
        return progress_enum(fmt, _progress(iter, size))

    helper_content = progress(req.iter_content(chunk_size=4096), size)

    if args.dev is False:
        content = StringIO()
        for chunk in helper_content:
            content.write(chunk)

        content.seek(0)

        print 'Extracting %s...' % helper
        if ext == 'zip':
            zip = zipfile.ZipFile(content, 'r')
            info = zip.getinfo('git-cinnabar/%s' % helper)
            helper_content = progress(zip.open(info), info.file_size)
        elif ext == 'tar.xz':
            def tar_extract():
                proc = subprocess.Popen(
                    ['tar', '-JxO', 'git-cinnabar/%s' % helper],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE)

                def send(stdin, content):
                    stdin.write(content)
                    stdin.close()

                thread = threading.Thread(
                    target=send, args=(proc.stdin, content.getvalue()))
                thread.start()

                chunk = True
                while chunk:
                    chunk = proc.stdout.read(4096)
                    yield chunk
                proc.wait()
                thread.join()

            helper_content = progress(tar_extract())

        else:
            assert False

    fd, path = tempfile.mkstemp(prefix=helper, dir=d)

    success = False
    try:
        for chunk in helper_content:
            os.write(fd, chunk)

        success = True
    finally:
        os.close(fd)
        if success:
            mode = os.stat(path).st_mode
            if args.output:
                helper_path = args.output
            else:
                helper_path = os.path.join(d, helper)
            try:
                # on Windows it's necessary to remove the file first.
                os.remove(helper_path)
            except OSError as exc:
                if exc.errno != errno.ENOENT:
                    raise
                pass
            os.rename(path, helper_path)
            # Add executable bits wherever read bits are set
            mode = mode | ((mode & 0444) >> 2)
            os.chmod(helper_path, mode)

            if not args.no_config:
                Git.run('config', '--global', 'cinnabar.helper',
                        os.path.abspath(helper_path))
        else:
            os.unlink(path)

    return 0
