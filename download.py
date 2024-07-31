#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

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
import re
import sys
import argparse
import platform
import tarfile
import tempfile
import time
import subprocess
import errno
from gzip import GzipFile
from shutil import copyfileobj, copyfile
from urllib.request import urlopen
from urllib.error import HTTPError
from zipfile import ZipFile
try:
    from CI.util import build_commit
except ImportError:
    build_commit = None


REPOSITORY = 'https://github.com/glandium/git-cinnabar'
AVAILABLE = (
    ('Linux', 'x86_64'),
    ('Linux', 'arm64'),
    ('macOS', 'x86_64'),
    ('macOS', 'arm64'),
    ('Windows', 'x86_64'),
)


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


def get_binary(system):
    binary = 'git-cinnabar'
    if system == 'Windows':
        binary += '.exe'
    return binary


def get_url(system, machine, variant, sha1):
    url = 'https://community-tc.services.mozilla.com/api/index/v1/task/'
    url += 'project.git-cinnabar.build.'
    url += '{}.{}.{}.{}'.format(
        sha1, system.lower(), machine,
        variant.lower() if variant else '').rstrip('.')
    url += '/artifacts/public/{}'.format(get_binary(system))

    return url


def get_release_url(system, machine, tag):
    ext = 'zip' if system == 'Windows' else 'tar.xz'
    url = f'{REPOSITORY}/releases/download/{tag}/git-cinnabar'
    url += f'.{system.lower()}.{machine}.{ext}'
    return url


def download(url, system, binary_path):
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
            self._start = self._t0 = time.monotonic()

        def show_progress(self):
            if self._length:
                count = f'\r {self._read * 100 // self._length}%'
            else:
                count = f'\r {self._read} bytes'
            sys.stderr.write(count)

        def read(self, length):
            data = self._reader.read(length)
            self._read += len(data)
            t1 = time.monotonic()
            if t1 - self._t0 > 0.1:
                self.show_progress()
                sys.stderr.flush()
            return data

        def finish(self):
            self.show_progress()
            sys.stderr.write('\n')
            sys.stderr.flush()

    encoding = reader.headers.get('Content-Encoding', 'identity')
    progress = ReaderProgress(reader, reader.length)
    binary_content = Seekable(progress, reader.length)
    if encoding == 'gzip':
        binary_content = GzipFile(mode='rb', fileobj=binary_content)

    (dirname, filename) = os.path.split(binary_path)
    fd, path = tempfile.mkstemp(prefix=filename, dir=dirname)
    fh = os.fdopen(fd, 'wb')

    success = False
    try:
        copyfileobj(binary_content, fh)
        success = True
    finally:
        progress.finish()
        fh.close()
        if success:
            if url.endswith(('.zip', '.tar.xz')):
                binary_name = get_binary(system)
                binary_content = None
                size = 0
                archive_path = path
                if url.endswith('.zip'):
                    archive = zip = ZipFile(path)
                    for info in zip.infolist():
                        if os.path.basename(info.filename) == binary_name:
                            size = info.file_size
                            binary_content = zip.open(info)
                            break
                elif url.endswith('tar.xz'):
                    archive = tar = tarfile.open(path, 'r:*')
                    while True:
                        member = tar.next()
                        if member is None:
                            break
                        if (member.isfile() and
                                os.path.basename(member.name) == binary_name):
                            size = member.size
                            binary_content = tar.extractfile(member)
                            break
                fd, path = tempfile.mkstemp(prefix=filename, dir=dirname)
                fh = os.fdopen(fd, 'wb')
                try:
                    print('Extracting %s...' % binary_name)
                    progress = ReaderProgress(binary_content, size)
                    copyfileobj(progress, fh)
                finally:
                    progress.finish()
                    fh.close()
                    binary_content.close()
                    archive.close()
                    os.unlink(archive_path)

            mode = os.stat(path).st_mode
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
            (stem, ext) = os.path.splitext(filename)
            remote_hg_path = os.path.join(dirname, "git-remote-hg" + ext)
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


def maybe_int(s):
    try:
        return int(s)
    except ValueError:
        return s


def split_version(s):
    s = s.decode('ascii')
    version = s.replace('-', '').split('.')
    version[-1:] = [x for x in re.split(r'([0-9]+)', version[-1]) if x]
    version = [maybe_int(x) for x in version]
    if isinstance(version[-1], int):
        version += ['z']
    return version


def main(args):
    if args.list:
        for system, machine in AVAILABLE:
            print("%s/%s" % (system, machine))
        return 0

    system = args.system
    machine = args.machine

    if system.startswith('MSYS_NT'):
        system = 'Windows'

    if system == 'Darwin':
        system = 'macOS'
    elif system == 'Windows':
        if machine == 'AMD64':
            machine = 'x86_64'
    if machine == 'aarch64':
        machine = 'arm64'

    if (system, machine) not in AVAILABLE:
        print('No download available for %s/%s' % (system, machine),
              file=sys.stderr)
        return 1

    tag = None
    local_sha1 = None
    if build_commit and not args.exact and not args.branch:
        try:
            local_sha1 = build_commit()
        except Exception:
            pass

    exact = args.exact or (not args.branch and local_sha1)
    branch = args.branch or 'release'

    if exact and not args.variant:
        if build_commit:
            tags = (
                (sha1, ref)
                for sha1, _, ref in (
                    l.split(None, 2)
                    for l in subprocess.check_output(
                        ['git', 'for-each-ref', 'refs/tags/']).splitlines()
                )
            )
        else:
            try:
                tags = (
                    tuple(l.split(None, 1))
                    for l in subprocess.check_output(
                        ['git', 'ls-remote', REPOSITORY, 'refs/tags/*'])
                        .splitlines()
                )
            except Exception:
                tags = ()

        if '.' in exact:
            ref = f'refs/tags/{exact}'.encode()
            matches = [
                sha1
                for sha1, r in tags
                if r == ref
            ]
            if not matches:
                print(f"Couldn't find a tag for {exact}")
                return 1
            tag = exact
            exact = matches[0]
        else:
            tags = [
                ref[len('refs/tags/'):]
                for sha1, ref in tags
                if sha1.decode('ascii') == exact
            ]
            tags = sorted(tags, key=lambda x: split_version(x), reverse=True)
            if tags:
                tag = tags[0].decode('ascii')

    if exact:
        sha1 = exact
    elif branch == 'release':
        if args.variant:
            print('Cannot use --variant without --branch {master,next}')
            return 1
        result = sorted(((sha1, ref[len('refs/tags/'):]) for sha1, ref in [
            l.split(b'\t', 1) for l in subprocess.check_output(
                ['git', 'ls-remote', REPOSITORY, 'refs/tags/*']
            ).splitlines()
        ]), key=lambda x: split_version(x[1]), reverse=True)
        if len(result) == 0:
            print('Could not find release tags')
            return 1
        sha1, tag = result[0]
        sha1 = sha1.decode('ascii')
        tag = tag.decode('ascii')
    elif branch:
        ref = f'refs/heads/{branch}'.encode('utf-8')
        result = [sha1 for sha1, ref_ in [
            l.split(b'\t', 1) for l in subprocess.check_output(
                ['git', 'ls-remote', REPOSITORY, ref]
            ).splitlines()]
            if ref == ref_
        ]
        if len(result) == 0:
            print(f'Could not find branch {branch}')
            return 1
        sha1 = result[0].decode('ascii')
    else:
        sha1 = None
    if sha1 is None:
        print('Cannot find the right binary for git-cinnabar.'
              ' Try --exact or --branch.',
              file=sys.stderr)
        return 1

    if tag:
        url = get_release_url(system, machine, tag)
    else:
        url = get_url(system, machine, args.variant, sha1)
    if args.url:
        print(url)
        return 0

    script_path = os.path.dirname(os.path.abspath(sys.argv[0]))

    if args.output:
        binary_path = args.output
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
        binary_path = os.path.join(d, get_binary(system))

    return download(url, system, binary_path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', action='store_true',
                        help='only print the download url')
    pgroup = parser.add_mutually_exclusive_group()
    pgroup.add_argument('--branch', metavar='BRANCH',
                        default=os.environ.get("GIT_CINNABAR_DOWNLOAD_BRANCH"),
                        help='download a build for the given branch')
    pgroup.add_argument('--exact', metavar='EXACT',
                        default=os.environ.get("GIT_CINNABAR_DOWNLOAD_EXACT"),
                        help='download a build for the given commit')
    parser.add_argument('--variant', metavar='VARIANT',
                        default=os.environ.get(
                            "GIT_CINNABAR_DOWNLOAD_VARIANT"),
                        help='download the given variant')
    parser.add_argument('--system', default=platform.system(),
                        help=argparse.SUPPRESS)
    parser.add_argument('--machine', default=platform.machine(),
                        help=argparse.SUPPRESS)
    parser.add_argument('-o', '--output', help=argparse.SUPPRESS)
    parser.add_argument('--list', action='store_true', help=argparse.SUPPRESS)
    sys.exit(main(parser.parse_args()))
