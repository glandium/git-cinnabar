import os
import sys


BASE_DIR = os.path.dirname(__file__)
sys.path.append(BASE_DIR)
sys.path.append(os.path.join(BASE_DIR, '..'))

from itertools import chain
from tasks import (
    parse_version,
    Task,
    TaskEnvironment,
    Tool,
)
from tools import (
    Git,
    Helper,
    Hg,
    old_compatible_python,
)
from variables import *  # noqa: F403


def git_rev_parse(committish):
    from cinnabar.git import Git
    from cinnabar.util import one
    return one(Git.iter('rev-parse', committish,
                        cwd=os.path.join(BASE_DIR, '..')))


MERCURIAL_VERSION = '4.6.2'
GIT_VERSION = '2.18.0'
UPGRADE_FROM = ('0.3.0', '0.3.2', '0.4.0', '0.5.0b2', '0.5.0b3')


def install_hg(name):
    hg = Hg.by_name(name)
    filename = os.path.basename(hg.artifacts[0])
    return [
        'curl -L {{{}.artifact}} -o {}'.format(hg, filename),
        'pip install {}'.format(filename)
    ]


def install_git(name):
    url = '{{{}.artifact}}'.format(Git.by_name(name))
    if name.startswith('linux.'):
        return [
            'curl -L {} | tar -C / -Jxf -'.format(url)
        ]
    else:
        return [
            'curl -L {} -o git.tar.bz2'.format(url),
            'tar -jxf git.tar.bz2',
        ]


def install_helper(name):
    helper = Helper.by_name(name)
    filename = os.path.basename(helper.artifacts[0])
    return [
        'curl --compressed -o {} -L {{{}.artifacts[0]}}'.format(
            filename, Helper.by_name(name)),
        'chmod +x {}'.format(filename),
        'git config --global cinnabar.helper $PWD/{}'.format(filename),
    ]


class TestTask(Task):
    coverage = []

    def __init__(self, **kwargs):
        git = kwargs.pop('git', GIT_VERSION)
        hg = kwargs.pop('hg', MERCURIAL_VERSION)
        commit = kwargs.pop('commit', None)
        task_env = kwargs.pop('task_env', 'linux')
        variant = kwargs.pop('variant', None)
        helper = kwargs.pop('helper', None)
        clone = kwargs.pop('clone', TC_COMMIT)
        desc = kwargs.pop('description', None)
        extra_desc = kwargs.pop('extra_desc', None)
        if helper is None:
            helper = '{}.{}'.format(task_env, variant) if variant else task_env
            helper = install_helper(helper)
        if variant:
            kwargs.setdefault('env', {})['VARIANT'] = variant
        env = TaskEnvironment.by_name('{}.test'.format(task_env))
        command = []
        if hg:
            command.extend(install_hg('{}.{}'.format(task_env, hg)))
        if git:
            command.extend(install_git('{}.{}'.format(task_env, git)))
        command.extend(Task.checkout(commit=commit))
        command.extend(helper)
        if clone:
            command.extend([
                'curl -L {{{}.artifact}} -o clone.tar.xz'.format(
                    Clone.by_name(clone)),
                'tar -C repo -Jxf clone.tar.xz',
            ])
        if 'command' in kwargs:
            kwargs['command'] = command + kwargs['command']
        else:
            kwargs['command'] = command + [
                'make -C repo -f CI/tests.mk',
            ]
        if variant == 'coverage':
            kwargs['command'].extend([
                'shopt -s nullglob',
                'for f in repo/git-core/{{cinnabar,connect,hg}}*.gcda',
                'do mv $f repo/helper',
                'done',
                'cd repo',
                'tar -Jcf $ARTIFACTS/coverage.tar.xz .coverage'
                ' helper/{{cinnabar,connect,hg}}*.gcda',
                'cd ..',
                'shopt -u nullglob',
            ])
            artifact = kwargs.pop('artifact', None)
            artifacts = kwargs.setdefault('artifacts', [])
            assert not(artifacts and artifact)
            if artifact:
                artifacts.push(artifact)
            artifacts.append('coverage.tar.xz')
            self.coverage.append(self)
        if not desc:
            desc = 'test w/ git-{} hg-{}'.format(git, hg)
            if variant and variant != 'coverage':
                desc = ' '.join((desc, variant))
        if extra_desc:
            desc = ' '.join((desc, extra_desc))
        if task_env != 'linux':
            desc = ' '.join((desc, env.os, env.cpu))
        kwargs['description'] = desc
        Task.__init__(self, task_env=env, **kwargs)


class Clone(TestTask):
    __metaclass__ = Tool
    PREFIX = "clone"

    def __init__(self, version):
        sha1 = git_rev_parse(version)
        expireIn = '26 weeks'
        if version == TC_COMMIT or len(version) == 40:
            if version == TC_COMMIT:
                download = install_helper('linux')
            else:
                download = install_helper('linux.old:{}'.format(version))
            expireIn = '26 weeks'
        elif parse_version(version) > parse_version('0.5.0a'):
            download = ['repo/git-cinnabar download']
        elif parse_version(version) == parse_version('0.4.0'):
            download = ['(cd repo ; ./git-cinnabar download)']
        else:
            download = []
        if parse_version(version) < parse_version('0.5.0b3'):
            hg = '4.3.3'
        else:
            hg = MERCURIAL_VERSION
        TestTask.__init__(
            self,
            hg=hg,
            description='clone w/ {}'.format(version),
            index='clone.{}'.format(sha1),
            expireIn=expireIn,
            helper=download,
            commit=sha1,
            clone=False,
            command=[
                'PATH=$PWD/repo:$PATH'
                ' git -c fetch.prune=true clone -n hg::$REPO hg.old.git',
                'tar -Jcf $ARTIFACTS/clone.tar.xz hg.old.git',
            ],
            artifact='clone.tar.xz',
            env={
                'REPO': 'https://hg.mozilla.org/users/mh_glandium.org/jqplot',
            },
        )


TestTask(
    description='python lint & tests',
    variant='coverage',
    clone=False,
    command=[
        '(cd repo &&'
        ' nosetests --all-modules --with-coverage --cover-tests tests)',
        '(cd repo && flake8 --ignore E402 $(git ls-files \*\*.py git-cinnabar'
        ' git-remote-hg))',
    ],
)

for env in ('linux', 'mingw64'):
    TestTask(task_env=env)

    requests = [] if env == 'linux' else ['pip install requests']
    task_env = TaskEnvironment.by_name('{}.test'.format(env))
    Task(
        task_env=task_env,
        description='download helper {} {}'.format(task_env.os, task_env.cpu),
        command=list(chain(
            install_git('{}.{}'.format(env, GIT_VERSION)),
            install_hg('{}.{}'.format(env, MERCURIAL_VERSION)),
            Task.checkout(),
            requests + [
                '(cd repo ; ./git-cinnabar download --dev)',
                'rm -rf repo/.git',
                '(cd repo ; ./git-cinnabar download --dev)',
            ],
        )),
        dependencies=[
            Helper.by_name(env),
        ],
    )

# Because nothing is using the x86 windows helper, we need to manually touch
# it.
Helper.by_name('mingw32')

for upgrade in UPGRADE_FROM:
    TestTask(
        extra_desc='upgrade-from-{}'.format(upgrade),
        variant='coverage',
        clone=upgrade,
        env={
            'UPGRADE_FROM': upgrade,
        },
    )

for git in ('1.8.5', '2.7.4'):
    TestTask(git=git)

for hg in ('1.9.3', '2.5.4', '2.6.3', '2.7.2', '3.0.1', '3.4.2', '3.6.3',
           '4.3.3', '4.4.2', '4.5.3'):
    TestTask(hg=hg)

# for hg in ('1.9.3', '2.0.2', '2.1.2', '2.2.3', '2.3.2', '2.4.2', '2.5.4',
#            '2.6.3', '2.7.2', '2.8.2', '2.9.1', '3.0.1', '3.1.2', '3.2.4',
#            '3.3.3', '3.4.2', '3.5.2', '3.6.3', '3.7.3', '3.8.4', '3.9.2',
#            '4.0.2', '4.1.3', '4.2.2', '4.3.3', '4.4.2', '4.5.3', '4.6.1'):
#     TestTask(hg=hg)

TestTask(
    variant='asan',
    env={
        'GIT_CINNABAR_EXPERIMENTS': 'true',
    },
)

TestTask(
    variant='old',
    env={
        'GIT_CINNABAR_OLD_HELPER': '1',
    },
)

rev = old_compatible_python()

TestTask(
    commit=rev,
    clone=rev,
    extra_desc='old python',
)

TestTask(
    variant='coverage',
    extra_desc='experiments',
    env={
        'GIT_CINNABAR_EXPERIMENTS': 'true',
    },
)

TestTask(
    variant='coverage',
    extra_desc='graft',
    env={
        'GRAFT': '1',
    },
)

if TC_IS_PUSH and TC_BRANCH:
    upload_coverage = []
    for task in TestTask.coverage:
        upload_coverage.extend([
            'curl -L {{{}.artifact}} | tar -Jxf -'.format(task),
            'codecov --name "{}" --commit {} --branch {}'.format(
                task.task['metadata']['name'], TC_COMMIT, TC_BRANCH),
            ('find . \( -name .coverage -o -name coverage.xml -o -name \*.gcda'
             ' -o -name \*.gcov \) -delete'),
        ])

    Task(
        task_env=TaskEnvironment.by_name('linux.codecov'),
        description='upload coverage',
        scopes=['secrets:get:repo:github.com/glandium.git-cinnabar:codecov'],
        command=list(chain(
            Task.checkout(),
            [
                'set +x',
                ('export CODECOV_TOKEN=$(curl -sL http://taskcluster/secrets'
                 '/v1/secret/repo:github.com/glandium.git-cinnabar:codecov | '
                 'python -c "import json, sys; print(json.load(sys.stdin)'
                 '[\\"secret\\"][\\"token\\"])")'),
                'set -x',
                'cd repo',
                'curl -L {{{}.artifacts[1]}} | tar -Jxf -'.format(
                    Helper.by_name('linux.coverage')),
            ],
            upload_coverage,
        )),
    )

for t in Task.by_id.itervalues():
    t.submit()
