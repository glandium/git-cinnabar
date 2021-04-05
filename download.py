#!/bin/sh
''':'
if command -v python3 > /dev/null; then
  PYTHON=python3
elif command -v python2.7 > /dev/null; then
  PYTHON=python2.7
elif command -v python2 > /dev/null; then
  PYTHON=python2
else
  echo "Could not find python 2.7 or 3.x" >&2
  exit 1
fi
exec $PYTHON $0 "$@"
exit 1
'''

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
import tempfile
import errno
from cinnabar.git import Git
from cinnabar.helper import helper_hash
from cinnabar.util import (
    HTTPReader,
    Progress,
    Seekable,
)
from gzip import GzipFile
from shutil import copyfileobj
try:
    from urllib2 import HTTPError
except ImportError:
    from urllib.error import HTTPError


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

    script_path = os.path.dirname(os.path.abspath(sys.argv[0]))

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
        args.variant.lower() if args.variant else '').rstrip('.')
    url += '/artifacts/public/{}'.format(helper)

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


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', action='store_true',
                        help='only print the download url')
    parser.add_argument('--variant', nargs=1, metavar='VARIANT',
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
