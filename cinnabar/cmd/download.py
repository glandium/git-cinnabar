from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)
import os
import sys
import argparse
import platform
import subprocess
import tempfile
import threading
import zipfile
import errno
from cinnabar import VERSION
from cinnabar.cmd.util import CLI
from cinnabar.git import Git
from cinnabar.helper import helper_hash
from cinnabar.util import (
    HTTPReader,
    Progress,
    Seekable,
)
from gzip import GzipFile
from io import BytesIO
from shutil import copyfileobj
try:
    from urllib2 import HTTPError
except ImportError:
    from urllib.error import HTTPError


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

    if system.startswith('MSYS_NT'):
        system = 'Windows'

    if system == 'Darwin':
        system = 'macOS'
    elif system == 'Windows':
        helper += '.exe'
        if machine == 'AMD64':
            machine = 'x86_64'

    available = (
        ('Linux', 'x86_64'),
        ('macOS', 'x86_64'),
        ('macOS', 'arm64'),
        ('Windows', 'x86_64'),
        ('Windows', 'x86'),
    )

    if args.list:
        for system, machine in available:
            print("%s/%s" % (system, machine))
        return 0

    if (system, machine) not in available:
        print('No download available for %s/%s' % (system, machine),
              file=sys.stderr)
        return 1

    if args.dev is False:
        version = VERSION
        if version.endswith('a'):
            # For version x.y.za, download a development helper
            args.dev = ''

    script_path = os.path.dirname(os.path.abspath(sys.argv[0]))

    if args.dev is not False:
        sha1 = helper_hash()
        if sha1 is None:
            print('Cannot find the right development helper for this '
                  'version of git cinnabar.',
                  file=sys.stderr)
            return 1
        url = 'https://community-tc.services.mozilla.com/api/index/v1/task/'
        url += 'project.git-cinnabar.helper.'
        url += '{}.{}.{}.{}'.format(
            sha1.decode('ascii'), system.lower(), machine,
            args.dev.lower() if args.dev else '').rstrip('.')
        url += '/artifacts/public/{}'.format(helper)

    else:
        if system in ('Windows', 'macOS'):
            ext = 'zip'
        else:
            ext = 'tar.xz'
        REPO_BASE = 'https://github.com/glandium'
        url = '%s/git-cinnabar/releases/download/%s/git-cinnabar.%s.%s.%s' % (
            REPO_BASE, version, system.lower(), machine.lower(), ext)

    if args.url:
        print(url)
        return 0

    if args.output:
        d = os.path.dirname(args.output)
    else:
        d = script_path
        if not os.access(d, os.W_OK):
            d = os.path.join(os.path.expanduser('~'), '.git-cinnabar')
            try:
                os.makedirs(d)
            except Exception:
                pass
            if not os.path.isdir(d):
                print('Cannot write to either %s or %s.' % (d, script_path),
                      file=sys.stderr)
                return 1

    print('Downloading from %s...' % url)
    try:
        reader = HTTPReader(url)
    except HTTPError:
        # Try again, just in case
        try:
            reader = HTTPReader(url)
        except HTTPError as e:
            print('Download failed with status code %d\n' % e.code,
                  file=sys.stderr)
            print(
                'Error body was:\n\n%s' % e.read().decode('utf-8', 'replace'),
                file=sys.stderr)
            return 1

    class ReaderProgress(object):
        def __init__(self, reader, length=None):
            self._reader = reader
            self._length = length
            self._read = 0
            self._progress = Progress(' {}%' if self._length else ' {} bytes')

        def read(self, length):
            data = self._reader.read(length)
            self._read += len(data)
            if self._length:
                count = self._read * 100 // self._length
            else:
                count = self._read
            self._progress.progress(count)
            return data

        def finish(self):
            self._progress.finish()

    encoding = reader.fh.headers.get('Content-Encoding', 'identity')
    progress = ReaderProgress(reader, reader.length)
    helper_content = Seekable(progress, reader.length)
    if encoding == 'gzip':
        helper_content = GzipFile(mode='rb', fileobj=helper_content)

    if args.dev is False:
        content = BytesIO()
        copyfileobj(helper_content, content)
        progress.finish()
        content.seek(0)

        print('Extracting %s...' % helper)
        if ext == 'zip':
            zip = zipfile.ZipFile(content, 'r')
            info = zip.getinfo('git-cinnabar/%s' % helper)
            helper_content = ReaderProgress(zip.open(info), info.file_size)
        elif ext == 'tar.xz':
            class UntarProgress(ReaderProgress):
                def __init__(self, content, helper):
                    self._proc = subprocess.Popen(
                        ['tar', '-JxO', 'git-cinnabar/%s' % helper],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE)

                    super(UntarProgress, self).__init__(self._proc.stdout)

                    class ExtractThread(threading.Thread):
                        def __init__(self, stdin, content):
                            super(ExtractThread, self).__init__()
                            self.stdin = stdin
                            self.content = content
                            self.exc = None

                        def run(self):
                            try:
                                copyfileobj(self.content, self.stdin)
                                self.stdin.close()
                            except Exception as e:
                                self.exc = e

                    self._thread = ExtractThread(self._proc.stdin, content)
                    self._thread.start()

                def finish(self):
                    self._proc.wait()
                    self._thread.join()
                    if self._thread.exc:
                        raise self._thread.exc
                    super(UntarProgress, self).finish()

            helper_content = UntarProgress(content, helper)

        else:
            assert False
        progress = helper_content

    fd, path = tempfile.mkstemp(prefix=helper, dir=d)
    fh = os.fdopen(fd, 'wb')

    success = False
    try:
        copyfileobj(helper_content, fh)
        success = True
    finally:
        progress.finish()
        fh.close()
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
            mode = mode | ((mode & 0o0444) >> 2)
            os.chmod(helper_path, mode)

            if not args.no_config:
                Git.run('config', '--global', 'cinnabar.helper',
                        os.path.abspath(helper_path))
        else:
            os.unlink(path)

    return 0
