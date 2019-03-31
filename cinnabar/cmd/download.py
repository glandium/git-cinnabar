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
from cinnabar.util import (
    HTTPReader,
    Progress,
)
from distutils.version import StrictVersion
from gzip import GzipFile
from shutil import copyfileobj
from urllib2 import HTTPError


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
        ('Windows', 'x86_64'),
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

    if args.dev is False:
        version = VERSION
        if version.endswith('a'):
            v = StrictVersion(version[:-1]).version + (0, 0, 0)
            if v[2] == 0:
                # For version x.y.0a, download a development helper
                args.dev = ''
            else:
                # For version x.y.za, download the helper from x.y.(z-1)
                version = '{}.{}.{}'.format(v[0], v[1], v[2] - 1)

    script_path = os.path.dirname(os.path.abspath(sys.argv[0]))

    if args.dev is not False:
        sha1 = helper_hash()
        if sha1 is None:
            print >>sys.stderr, (
                'Cannot find the right development helper for this '
                'version of git cinnabar.')
            return 1
        url = 'https://index.taskcluster.net/v1/task/github'
        url += '.glandium.git-cinnabar.helper.'
        url += '{}.{}.{}.{}'.format(
            sha1, system.lower(), machine,
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
        print url
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
                print >>sys.stderr, (
                    'Cannot write to either %s or %s.' % (d, script_path))
                return 1

    print 'Downloading from %s...' % url
    try:
        reader = HTTPReader(url)
    except HTTPError:
        # Try again, just in case
        try:
            reader = HTTPReader(url)
        except HTTPError as e:
            print >>sys.stderr, (
                'Download failed with status code %d\n' % e.code)
            print >>sys.stderr, 'Error body was:\n\n%s' % e.read()
            return 1

    class ReaderProgress(object):
        def __init__(self, reader, length=None):
            self._reader = reader
            self._length = length
            self._read = 0
            self._pos = 0
            self._buf = ''
            self._progress = Progress(' {}%' if self._length else ' {} bytes')

        def read(self, length):
            # See comment above tell
            if self._pos < self._read:
                assert self._read - self._pos <= 8
                assert length <= len(self._buf)
                data = self._buf[:length]
                self._buf = self._buf[length:]
                self._pos += length
            else:
                assert self._read == self._pos
                data = self._reader.read(length)
                self._read += len(data)
                self._pos = self._read
                # Keep the last 8 bytes we read for GzipFile
                self._buf = data[-8:]
            self.progress()
            return data

        def progress(self):
            if self._length:
                count = self._read * 100 / self._length
            else:
                count = self._read
            self._progress.progress(count)

        def finish(self):
            self._progress.finish()

        # GzipFile wants to seek to the end of the file and back, so we add
        # enough tell/seek support to make it happy. It also rewinds 8 bytes
        # for the CRC, so we also handle that.
        def tell(self):
            return self._pos

        def seek(self, pos, how=os.SEEK_SET):
            if how == os.SEEK_END:
                self._pos = self._length + pos
            elif how == os.SEEK_SET:
                self._pos = pos
            elif how == os.SEEK_CUR:
                self._pos += pos
            else:
                raise NotImplementedError()
            return self._pos

    encoding = reader.fh.headers.get('Content-Encoding', 'identity')
    helper_content = ReaderProgress(reader, reader.length)
    if encoding == 'gzip':
        class WrapGzipFile(GzipFile):
            def finish(self):
                self.fileobj.finish()
        helper_content = WrapGzipFile(mode='rb', fileobj=helper_content)

    if args.dev is False:
        content = StringIO()
        copyfileobj(helper_content, content)
        if hasattr(helper_content, 'finish'):
            helper_content.finish()
        content.seek(0)

        print 'Extracting %s...' % helper
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

                    def send(stdin, content):
                        copyfileobj(content, stdin)
                        stdin.close()

                    self._thread = threading.Thread(
                        target=send, args=(self._proc.stdin, content))
                    self._thread.start()

                def finish(self):
                    self._proc.wait()
                    self._thread.join()
                    super(UntarProgress, self).finish()

            helper_content = UntarProgress(content, helper)

        else:
            assert False

    fd, path = tempfile.mkstemp(prefix=helper, dir=d)
    fh = os.fdopen(fd, 'wb')

    success = False
    try:
        copyfileobj(helper_content, fh)
        success = True
    finally:
        if hasattr(helper_content, 'finish'):
            helper_content.finish()
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
            mode = mode | ((mode & 0444) >> 2)
            os.chmod(helper_path, mode)

            if not args.no_config:
                Git.run('config', '--global', 'cinnabar.helper',
                        os.path.abspath(helper_path))
        else:
            os.unlink(path)

    return 0
