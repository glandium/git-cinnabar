from __future__ import print_function

import os

from tasks import (
    Task,
    TaskEnvironment,
    Tool,
    parse_version,
)
from docker import DockerImage
import msys
from cinnabar.cmd.util import helper_hash


class Git(Task):
    __metaclass__ = Tool
    PREFIX = "git"

    def __init__(self, os_and_version):
        (os, version) = os_and_version.split('.', 1)
        build_image = DockerImage.by_name('build')
        if os == 'linux':
            Task.__init__(
                self,
                task_env=build_image,
                description='git v{}'.format(version),
                index='{}.git.v{}'.format(build_image.hexdigest, version),
                expireIn='26 weeks',
                command=Task.checkout(
                    'git://git.kernel.org/pub/scm/git/git.git',
                    'v{}'.format(version)
                ) + [
                    'make -C repo -j$(nproc) install prefix=/usr'
                    ' NO_GETTEXT=1 NO_OPENSSL=1 NO_TCLTK=1'
                    ' DESTDIR=/tmp/git-install',
                    'tar -C /tmp/git-install -Jcf $ARTIFACTS/git-{}.tar.xz .'
                    .format(version),
                ],
                artifact='git-{}.tar.xz'.format(version),
            )
        else:
            env = TaskEnvironment.by_name('{}.build'.format(os))
            raw_version = version
            if 'windows' not in version:
                version = {
                    version: version + '.windows.1',
                    '2.17.1': '2.17.1.windows.2',
                }.get(version)
            if version.endswith('.windows.1'):
                min_ver = version[:-len('.windows.1')]
            else:
                min_ver = version.replace('windows.', '')
            Task.__init__(
                self,
                task_env=build_image,
                description='git v{} {} {}'.format(version, env.os, env.cpu),
                index='{}.git.v{}'.format(os, raw_version),
                expireIn='26 weeks',
                command=[
                    'curl -L https://github.com/git-for-windows/git/releases/'
                    'download/v{}/MinGit-{}-{}-bit.zip'
                    ' -o git.zip'.format(version, min_ver, msys.bits(env.cpu)),
                    'unzip -d git git.zip',
                    'tar -jcf $ARTIFACTS/git-{}.tar.bz2 git'.format(
                        raw_version),
                ],
                artifact='git-{}.tar.bz2'.format(raw_version),
            )


class Hg(Task):
    __metaclass__ = Tool
    PREFIX = "hg"

    def __init__(self, os_and_version):
        (os, version) = os_and_version.split('.', 1)
        env = TaskEnvironment.by_name('{}.build'.format(os))

        desc = 'hg v{}'.format(version)
        if os == 'linux':
            artifact = 'mercurial-{}-cp27-none-linux_x86_64.whl'
        else:
            desc = '{} {} {}'.format(desc, env.os, env.cpu)
            artifact = 'mercurial-{}-cp27-cp27m-mingw.whl'

        # 2.6.2 is the first version available on pypi
        if parse_version('2.6.2') <= parse_version(version):
            source = 'mercurial=={}'
        else:
            source = 'https://mercurial-scm.org/release/mercurial-{}.tar.gz'

        Task.__init__(
            self,
            task_env=env,
            description=desc,
            index='{}.hg.v{}'.format(env.hexdigest, version),
            expireIn='26 weeks',
            command=(
                'pip wheel -v --build-option -b --build-option $PWD/wheel'
                ' -w $ARTIFACTS {}'.format(source.format(version)),
            ),
            artifact=artifact.format(version),
        )


def old_helper_head():
    from cinnabar.git import Git
    from cinnabar.helper import GitHgHelper
    version = GitHgHelper.VERSION
    return list(Git.iter(
        'log', 'HEAD', '--format=%H', '--pickaxe-regex',
        '-S', '#define CMD_VERSION {}'.format(version),
        cwd=os.path.join(os.path.dirname(__file__), '..')))[-1]


def old_helper_hash(head):
    from cinnabar.git import Git, split_ls_tree
    from cinnabar.util import one
    return split_ls_tree(one(Git.iter(
        'ls-tree', head, 'helper',
        cwd=os.path.join(os.path.dirname(__file__), '..'))))[2]


class Helper(Task):
    __metaclass__ = Tool
    PREFIX = 'helper'

    def __init__(self, os_and_variant):
        os, variant = (os_and_variant.split('.', 2) + [''])[:2]
        env = TaskEnvironment.by_name('{}.build'.format(os))

        artifact = 'git-cinnabar-helper'
        if os != 'linux':
            artifact += '.exe'
        artifacts = [artifact]

        def prefix(p, s):
            return p + s if s else s

        make_flags = ''
        hash = None
        head = None
        desc_variant = variant
        extra_commands = []
        if variant == 'asan':
            make_flags = ('CFLAGS="-O2 -g -fsanitize=address"'
                          ' LDFLAGS=-static-libasan')
        elif variant == 'coverage':
            make_flags = 'CFLAGS="-coverage"'
            artifacts += ['coverage.tar.xz']
            extra_commands = [
                'mv repo/git-core/{{cinnabar,connect,hg}}*.gcno repo/helper',
                '(cd repo && tar -Jcf $ARTIFACTS/coverage.tar.xz'
                ' helper/{{cinnabar,connect,hg}}*.gcno)',
            ]
        elif variant == 'old':
            head = old_helper_head()
            hash = old_helper_hash(head)
            variant = ''
        elif variant:
            raise Exception('Unknown variant: {}'.format(variant))
        hash = hash or helper_hash()

        Task.__init__(
            self,
            task_env=env,
            description='helper {} {}{}'.format(
                env.os, env.cpu, prefix(' ', desc_variant)),
            index='helper.{}.{}.{}{}'.format(
                hash, env.os, env.cpu, prefix('.', variant)),
            expireIn='26 weeks',
            command=Task.checkout(commit=head) + [
                'make -C repo -j $(nproc) helper prefix=/usr{}'.format(
                    prefix(' ', make_flags)),
                'mv repo/{} $ARTIFACTS/'.format(artifact),
            ] + extra_commands,
            artifacts=artifacts,
        )
