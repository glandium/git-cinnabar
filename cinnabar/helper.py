import atexit
import functools
import logging
import os
import re
import subprocess
from .git import (
    Git,
    GitProcess,
    Mark,
    NULL_NODE_ID,
    sha1path,
)
from .util import (
    check_enabled,
    one,
    sorted_merge,
)
from contextlib import contextmanager
from itertools import chain


SHA1_RE = re.compile('^[0-9a-fA-F]{40}$')


class NoHelperException(Exception):
    pass


class HelperClosedException(Exception):
    pass


class GitHgNoHelper(object):
    _last_manifest = None

    @classmethod
    def cat_file(self, typ, sha1):
        return Git.cat_file(typ, sha1)

    @classmethod
    def git2hg(self, sha1):
        if not SHA1_RE.match(sha1):
            sha1 = one(Git.iter('rev-parse', '--revs-only', sha1))
        return Git.read_note('refs/notes/cinnabar', sha1)

    @classmethod
    def hg2git(self, hg_sha1):
        if len(hg_sha1) < 40:
            path = sha1path(hg_sha1)
            dir, partial = path.rsplit('/', 1)
            matches = []
            for ls in Git.ls_tree('refs/cinnabar/hg2git', dir + '/'):
                mode, typ, gitsha1, path = ls
                if path.startswith(partial):
                    matches.append(gitsha1)
            if len(matches) == 1:
                return matches[0]
            ls = None
        else:
            ls = one(Git.ls_tree('refs/cinnabar/hg2git',
                                 sha1path(hg_sha1)))
        if not ls:
            return NULL_NODE_ID
        mode, typ, gitsha1, path = ls
        return gitsha1

    @classmethod
    def _manifest(self, hg_sha1, git_sha1):
        from githg import ManifestLine, GitHgStore
        if self._last_manifest:
            gitreference, reference_lines = self._last_manifest
            changes = []
            hg_diff = list(Git.diff_tree(gitreference, git_sha1,
                                         'hg', recursive=True))
            git_diff = list(Git.diff_tree(gitreference, git_sha1,
                                          'git', recursive=True))
            for line in sorted_merge(hg_diff, git_diff,
                                     key=lambda i: i[-1].split('/', 1)[1],
                                     non_key=lambda i: (i[1], i[3], i[4])):
                path, hg_change, git_change = line
                status = hg_change[2] if hg_change else git_change[2]
                if status == 'D':
                    changes.append((path, None))
                else:
                    assert status in 'AM'
                    node = hg_change[1] if hg_change else None
                    attr = GitHgStore.ATTR[git_change[0]] if git_change \
                        else None
                    changes.append((path, (node, attr)))

            lines = ((l.name, l) for l in reference_lines)
            for line in sorted_merge(lines, changes, non_key=lambda i: i[1]):
                path, manifest_line, change = line
                if change:
                    node, attr = change
                    if node is None:
                        node = manifest_line.node
                    if attr is None:
                        attr = manifest_line.attr
                    yield ManifestLine(path, node, attr)
                elif change is not None:
                    yield manifest_line
        else:
            attrs = {}
            for mode, typ, filesha1, path in Git.ls_tree(git_sha1,
                                                         recursive=True):
                if path.startswith('git/'):
                    attr = GitHgStore.ATTR[mode]
                    if attr:
                        attrs[path[4:]] = attr
                else:
                    assert path.startswith('hg/')
                    path = path[3:]
                    line = ManifestLine(
                        name=path,
                        node=filesha1,
                        attr=attrs.get(path, ''),
                    )
                    yield line

    @classmethod
    def manifest(self, hg_sha1):
        git_sha1 = self.hg2git(hg_sha1)
        lines = list(self._manifest(hg_sha1, git_sha1))
        self._last_manifest = (git_sha1, lines)
        return lines


def helpermethod(func):
    @functools.wraps(func)
    def wrapper(cls, *args, **kwargs):
        check = check_enabled('helper')
        try:
            result = func(cls, *args, **kwargs)
            if not check:
                return result
        except NoHelperException:
            if check:
                raise Exception('Helper check enabled but helper not found.')
        except HelperClosedException:
            check = False
        result2 = getattr(GitHgNoHelper, func.__name__)(*args, **kwargs)
        if check:
            if func.__name__ == 'manifest':
                # GitHgNoHelper.manifest returns a list, while
                # GitHgHelper.manifest returns a str. Normalize.
                result2 = ''.join(l._str for l in result2)
            if result != result2:
                raise Exception(
                    'Result difference between native and python for %s(%s)'
                    % (func.__name__,
                       ', '.join(chain((repr(a) for a in args),
                                       ('%s=%s' % (k, repr(v)) for k, v in
                                        sorted(kwargs.iteritems()))))))
        return result2
    return classmethod(wrapper)


class BaseHelper(object):
    @classmethod
    def close(self, keep_process=False):
        if not keep_process and self._helper and self._helper is not self:
            self._helper.wait()
        self._helper = self

    @classmethod
    @contextmanager
    def query(self, name, *args):
        if self._helper is False:
            helper_path = Git.config('cinnabar.helper')
            if helper_path == '':
                self._helper = None
        if self._helper is False:
            config = {'core.ignorecase': 'false'}
            if helper_path and os.path.exists(helper_path):
                config['alias.cinnabar-helper'] = '!' + helper_path
            stderr = None if check_enabled('helper') else open(os.devnull, 'w')
            self._helper = GitProcess('cinnabar-helper', stdin=subprocess.PIPE,
                                      stderr=stderr, config=config)
            self._helper.stdin.write('version %d\n' % self.VERSION)
            if not self._helper.stdout.readline():
                logger = logging.getLogger('helper')
                if self._helper.wait() == 128:
                    logger.warn(
                        'Cinnabar helper executable is outdated. '
                        'Please try `git cinnabar download` or rebuild it.')
                else:
                    logger.warn(
                        'Cannot find cinnabar helper executable. '
                        'Please try `git cinnabar download` or build it.')
                    logger.warn(
                        'You can disable this warning with '
                        '`git config cinnabar.helper ""`.')
                self._helper = None

        if not self._helper:
            raise NoHelperException
        if self._helper is self:
            raise HelperClosedException
        helper = self._helper
        if args:
            helper.stdin.write('%s %s\n' % (name, ' '.join(args)))
        else:
            helper.stdin.write('%s\n' % name)
        yield helper.stdout

    @classmethod
    def _read_file(self, expected_typ, stdout):
        hg_sha1 = stdout.read(41)
        if hg_sha1[-1] == '\n':
            assert hg_sha1[:40] == NULL_NODE_ID
            if expected_typ == 'auto':
                return 'missing', None
            return None
        typ, size = stdout.readline().split()
        size = int(size)
        assert expected_typ == 'auto' or typ == expected_typ
        ret = stdout.read(size)
        lf = stdout.read(1)
        assert lf == '\n'
        if expected_typ == 'auto':
            return typ, ret
        return ret

    @classmethod
    def _read_data(self, stdout):
        size = int(stdout.readline().strip())
        ret = stdout.read(size)
        lf = stdout.read(1)
        assert lf == '\n'
        return ret


class GitHgHelper(BaseHelper):
    VERSION = 4
    _helper = False

    @helpermethod
    def cat_file(self, typ, sha1):
        if isinstance(sha1, Mark):
            return GitHgNoHelper.cat_file(typ, sha1)
        with self.query('cat-file', sha1) as stdout:
            return self._read_file(typ, stdout)

    @helpermethod
    def git2hg(self, sha1):
        with self.query('git2hg', sha1) as stdout:
            return self._read_file('blob', stdout)

    @helpermethod
    def hg2git(self, hg_sha1):
        with self.query('hg2git', hg_sha1) as stdout:
            sha1 = stdout.read(41)
            assert sha1[-1] == '\n'
            return sha1[:40]

    @helpermethod
    def manifest(self, hg_sha1):
        with self.query('manifest', hg_sha1) as stdout:
            return self._read_data(stdout)


atexit.register(GitHgHelper.close)


class HgRepoHelper(BaseHelper):
    VERSION = 4
    _helper = False

    @classmethod
    def connect(self, url):
        with self.query('connect', url) as stdout:
            resp = stdout.readline().rstrip()
            if resp != 'ok':
                raise Exception(resp)

    @classmethod
    def state(self):
        with self.query('state') as stdout:
            return {
                'branchmap': self._read_data(stdout),
                'heads': self._read_data(stdout),
                'bookmarks': self._read_data(stdout),
            }

    @classmethod
    def capable(self, name):
        with self.query('capable', name) as stdout:
            return self._read_data(stdout)

    @classmethod
    def known(self, nodes):
        with self.query('known', *nodes) as stdout:
            return self._read_data(stdout)

    @classmethod
    def listkeys(self, namespace):
        with self.query('listkeys', namespace) as stdout:
            return self._read_data(stdout)

    @classmethod
    def getbundle(self, heads, common, bundle2caps=False):
        with self.query('getbundle', ','.join(heads), ','.join(common),
                        bundle2caps) as stdout:
            return stdout

    @classmethod
    def unbundle(self, input_iterator, heads):
        with self.query('unbundle', *heads) as stdout:
            for data in input_iterator:
                self._helper.stdin.write(data)
            ret = self._read_data(stdout)
            try:
                return int(ret)
            except ValueError:
                return ret

    @classmethod
    def pushkey(self, namespace, key, old, new):
        with self.query("pushkey", namespace, key, old, new) as stdout:
            ret = self._read_data(stdout).rstrip()
            try:
                return bool(int(ret))
            except ValueError:
                return ret

    @classmethod
    def lookup(self, key):
        with self.query("lookup", key) as stdout:
            success, data = self._read_data(stdout).rstrip().split(' ', 1)
            return data if int(success) else None


atexit.register(HgRepoHelper.close)
