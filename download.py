#!/bin/sh
''':'
if command -v python3 > /dev/null; then
  PYTHON=python3
else
  echo "Could not find python 3.x" >&2
  exit 1
fi
exec $PYTHON -B $0 "$@"
exit 1
'''
import os
import sys
import argparse
import platform
import tempfile
import errno
from CI.util import build_commit
from cinnabar.util import (
    Progress,
)
from gzip import GzipFile
from shutil import copyfileobj, copyfile
from urllib.request import urlopen
from urllib.error import HTTPError


# Transforms a File object without seek() or tell() into one that has.
# This only implements enough to make GzipFile happy. It wants to seek to
# the end of the file and back ; it also rewinds 8 bytes for the CRC.
class Seekable(object):
    def __init__(self, reader, length):
        self._reader = reader
        self._length = length
        self._read = 0
        self._pos = 0
        self._buf = b''

    def read(self, length):
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
        return data

    def tell(self):
        return self._pos

    def seek(self, pos, how=os.SEEK_SET):
        if how == os.SEEK_END:
            if pos:
                raise NotImplementedError()
            self._pos = self._length
        elif how == os.SEEK_SET:
            self._pos = pos
        elif how == os.SEEK_CUR:
            self._pos += pos
        else:
            raise NotImplementedError()
        return self._pos


def download(args):
    '''download a prebuilt binary'''

    binary = 'git-cinnabar'
    system = args.system
    machine = args.machine

    default_platform = (system == platform.system() and
                        machine == platform.machine())

    if system.startswith('MSYS_NT'):
        system = 'Windows'

    if system == 'Darwin':
        system = 'macOS'
    elif system == 'Windows':
        binary += '.exe'
        if machine == 'AMD64':
            machine = 'x86_64'
    if machine == 'aarch64':
        machine = 'arm64'

    available = (
        ('Linux', 'x86_64'),
        ('Linux', 'arm64'),
        ('macOS', 'x86_64'),
        ('macOS', 'arm64'),
        ('Windows', 'x86_64'),
    )

    if args.list:
        for system, machine in available:
            print("%s/%s" % (system, machine))
        return 0

    if (system, machine) not in available:
        print('No download available for %s/%s' % (system, machine),
              file=sys.stderr)
        return 1

    script_path = os.path.dirname(os.path.abspath(sys.argv[0]))

    sha1 = build_commit()
    if sha1 is None:
        print('Cannot find the right development binary for this '
              'version of git cinnabar.',
              file=sys.stderr)
        return 1
    url = 'https://community-tc.services.mozilla.com/api/index/v1/task/'
    url += 'project.git-cinnabar.build.'
    url += '{}.{}.{}.{}'.format(
        sha1, system.lower(), machine,
        args.variant.lower() if args.variant else '').rstrip('.')
    url += '/artifacts/public/{}'.format(binary)

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
        reader = urlopen(url)
    except HTTPError:
        # Try again, just in case
        try:
            reader = urlopen(url)
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

    encoding = reader.headers.get('Content-Encoding', 'identity')
    progress = ReaderProgress(reader, reader.length)
    binary_content = Seekable(progress, reader.length)
    if encoding == 'gzip':
        binary_content = GzipFile(mode='rb', fileobj=binary_content)

    fd, path = tempfile.mkstemp(prefix=binary, dir=d)
    fh = os.fdopen(fd, 'wb')

    success = False
    try:
        copyfileobj(binary_content, fh)
        success = True
    finally:
        progress.finish()
        fh.close()
        if success:
            mode = os.stat(path).st_mode
            if args.output:
                binary_path = args.output
            else:
                binary_path = os.path.join(d, binary)
            try:
                # on Windows it's necessary to remove the file first.
                os.remove(binary_path)
            except OSError as exc:
                if exc.errno != errno.ENOENT:
                    raise
            os.rename(path, binary_path)
            # Add executable bits wherever read bits are set
            mode = mode | ((mode & 0o0444) >> 2)
            os.chmod(binary_path, mode)
            (dirname, filename) = os.path.split(binary_path)
            (stem, ext) = os.path.splitext(filename)
            remote_hg_path = os.path.join(dirname, "git-remote-hg" + ext)
            if default_platform and not args.no_config:
                try:
                    os.unlink(remote_hg_path)
                except OSError as exc:
                    if exc.errno != errno.ENOENT:
                        raise
                try:
                    os.symlink(filename, remote_hg_path)
                except (AttributeError, OSError):
                    copyfile(binary_path, remote_hg_path)
                    os.chmod(remote_hg_path, mode)

        else:
            os.unlink(path)

    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', action='store_true',
                        help='only print the download url')
    parser.add_argument('--variant', metavar='VARIANT',
                        help='download the given variant')
    parser.add_argument('--system', default=platform.system(),
                        help=argparse.SUPPRESS)
    parser.add_argument('--machine', default=platform.machine(),
                        help=argparse.SUPPRESS)
    parser.add_argument('-o', '--output', help=argparse.SUPPRESS)
    parser.add_argument('--no-config', action='store_true',
                        help=argparse.SUPPRESS)
    parser.add_argument('--list', action='store_true', help=argparse.SUPPRESS)
    download(parser.parse_args())
