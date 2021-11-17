import hashlib
import json
import os
import sys


BASE_DIR = os.path.dirname(__file__)
sys.path.append(BASE_DIR)
sys.path.append(os.path.join(BASE_DIR, '..'))

from distutils.version import StrictVersion
from itertools import chain

import osx  # noqa: F401
from tasks import (
    action,
    parse_version,
    Task,
    TaskEnvironment,
    Tool,
)
from tools import (
    GIT_VERSION,
    MERCURIAL_VERSION,
    ALL_MERCURIAL_VERSIONS,
    SOME_MERCURIAL_VERSIONS,
    Git,
    Helper,
    Hg,
    nproc,
    old_compatible_python,
)
from variables import *  # noqa: F403


def git_rev_parse(committish):
    from cinnabar.git import Git
    from cinnabar.util import one
    return one(Git.iter('rev-parse', committish,
                        cwd=os.path.join(BASE_DIR, '..'))).decode()


UPGRADE_FROM = ('0.3.0', '0.3.2', '0.4.0', '0.5.0b2', '0.5.0b3')


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
        short_desc = kwargs.pop('short_desc', 'test')
        extra_desc = kwargs.pop('extra_desc', None)
        pre_command = kwargs.pop('pre_command', None)
        if helper is None:
            helper = '{}.{}'.format(task_env, variant) if variant else task_env
            helper = Helper.install(helper)
        if variant:
            kwargs.setdefault('env', {})['VARIANT'] = variant
        env = TaskEnvironment.by_name('{}.test'.format(task_env))
        command = []
        if pre_command:
            command.extend(pre_command)
        if hg:
            command.extend(Hg.install('{}.{}'.format(task_env, hg)))
            command.append('hg --version')
            try:
                if StrictVersion(hg) < '3.6':
                    kwargs.setdefault('env', {})['NO_CLONEBUNDLES'] = '1'
            except ValueError:
                # `hg` is a sha1 for trunk, which means it's >= 3.6
                pass
        if git:
            command.extend(Git.install('{}.{}'.format(task_env, git)))
            command.append('git --version')
        command.extend(Task.checkout(commit=commit))
        command.extend(helper)
        if clone:
            command.extend([
                'curl --compressed -L {{{}.artifact}} -o repo/bundle.git'
                .format(Clone.by_name(clone)),
                'git init repo/hg.old.git',
                'git -C repo/hg.old.git fetch ../bundle.git refs/*:refs/*',
                'git -C repo/hg.old.git remote add origin hg:${{REPO#https:}}',
                'git -C repo/hg.old.git symbolic-ref HEAD'
                ' refs/heads/branches/default/tip',
            ])
            kwargs.setdefault('env', {})['REPO'] = REPO
        command.extend((
            'repo/git-cinnabar --version',
            'GIT_CINNABAR_COVERAGE= repo/git-cinnabar python --version',
        ))
        if variant == 'coverage':
            command = [
                'export GIT_CINNABAR_COVERAGE=1',
                'export COVERAGE_FILE=$PWD/repo/.coverage',
            ] + command

        if 'command' in kwargs:
            kwargs['command'] = command + kwargs['command']
        else:
            if commit:
                # Always use the current CI scripts
                command.append('git -C repo checkout {} CI'.format(TC_COMMIT))
            output_sync = ' --output-sync=target'
            if env.os == 'macos':
                output_sync = ''
            kwargs['command'] = command + [
                'make -C repo -f CI/tests.mk -j$({}){}'
                .format(nproc(env), output_sync),
            ]

        if variant == 'coverage':
            kwargs['command'].extend([
                'shopt -s nullglob',
                'for f in repo/git-core/{{cinnabar,connect,hg}}*.gcda',
                'do mv $f repo/helper',
                'done',
                'cd repo',
                'zip $ARTIFACTS/coverage.zip .coverage'
                ' helper/{{cinnabar,connect,hg}}*.gcda',
                'cd ..',
                'shopt -u nullglob',
            ])
            artifact = kwargs.pop('artifact', None)
            artifacts = kwargs.setdefault('artifacts', [])
            assert not(artifacts and artifact)
            if artifact:
                artifacts.push(artifact)
            artifacts.append('coverage.zip')
            self.coverage.append(self)
        if not desc:
            desc = '{} w/ git-{} hg-{}'.format(
                short_desc, git, 'r' + hg if len(hg) == 40 else hg)
            if variant and variant != 'coverage':
                desc = ' '.join((desc, variant))
        if extra_desc:
            desc = ' '.join((desc, extra_desc))
        if task_env != 'linux':
            desc = ' '.join((desc, env.os, env.cpu))
        kwargs['description'] = desc
        Task.__init__(self, task_env=env, **kwargs)


class Clone(TestTask, metaclass=Tool):
    PREFIX = "clone"

    def __init__(self, version):
        sha1 = git_rev_parse(version)
        expireIn = '26 weeks'
        if version == TC_COMMIT or len(version) == 40:
            if version == TC_COMMIT:
                download = Helper.install('linux')
            else:
                download = Helper.install('linux.old:{}'.format(version))
            expireIn = '26 weeks'
        elif parse_version(version) > parse_version('0.5.0a'):
            download = ['repo/git-cinnabar download']
        elif parse_version(version) == parse_version('0.4.0'):
            download = ['(cd repo ; ./git-cinnabar download)']
        else:
            download = []
        if (parse_version(version) < parse_version('0.5.0b3') and
                version != TC_COMMIT):
            hg = '4.3.3'
        else:
            hg = MERCURIAL_VERSION
        kwargs = {}
        if parse_version(version) < parse_version('0.5.7'):
            kwargs['git'] = '2.30.2'
        if REPO == DEFAULT_REPO:
            index = 'bundle.{}'.format(sha1)
        else:
            index = 'bundle.{}.{}'.format(hashlib.sha1(REPO).hexdigest(), sha1)
        TestTask.__init__(
            self,
            hg=hg,
            description='clone w/ {}'.format(version),
            index=index,
            expireIn=expireIn,
            helper=download,
            commit=sha1,
            clone=False,
            command=[
                'PATH=$PWD/repo:$PATH'
                ' git -c fetch.prune=true clone -n hg::$REPO hg.old.git',
                'git -C hg.old.git bundle create $ARTIFACTS/bundle.git --all',
            ],
            artifact='bundle.git',
            env={
                'REPO': REPO,
            },
            priority='high',
            **kwargs,
        )


@action('decision')
def decision():
    TestTask(
        description='python lint & tests',
        variant='coverage',
        clone=False,
        command=[
            '(cd repo &&'
            ' nosetests --all-modules --with-coverage --cover-tests tests &&'
            ' nosetests3 --all-modules tests)',
            '(cd repo && python2.7 -m flake8 --ignore E402,F405'
            ' $(git ls-files \\*\\*.py git-cinnabar git-remote-hg'
            ' | grep -v ^CI/))',
            '(cd repo && flake8 --ignore E402,F405'
            ' $(git ls-files CI/\\*\\*.py)'
            ' $(git grep -l unicode_literals))',
        ],
    )

    for env in ('linux', 'mingw64', 'osx'):
        # Can't spawn osx workers from pull requests.
        if env.startswith('osx') and not TC_IS_PUSH:
            continue

        TestTask(task_env=env)

        task_env = TaskEnvironment.by_name('{}.test'.format(env))
        Task(
            task_env=task_env,
            description='download helper {} {}'.format(task_env.os,
                                                       task_env.cpu),
            command=list(chain(
                Git.install('{}.{}'.format(env, GIT_VERSION)),
                Hg.install('{}.{}'.format(env, MERCURIAL_VERSION)),
                Task.checkout(),
                [
                    '(cd repo ; ./git-cinnabar download --dev)',
                    'rm -rf repo/.git',
                    '(cd repo ; ./git-cinnabar download --dev)',
                    '(cd repo ; ./git-cinnabar download)',
                ],
            )),
            dependencies=[
                Helper.by_name(env),
            ],
        )

    # Because nothing is using the x86 windows helper, we need to manually
    # touch it.
    Helper.by_name('mingw32')
    # Same for arm64 mac
    if TC_IS_PUSH:
        Helper.by_name('arm64-osx')

    for upgrade in UPGRADE_FROM:
        TestTask(
            short_desc='upgrade tests',
            extra_desc='from-{}'.format(upgrade),
            variant='coverage',
            clone=upgrade,
            env={
                'UPGRADE_FROM': upgrade,
            },
            hg='5.4.2',
        )
        TestTask(
            short_desc='upgrade tests',
            extra_desc='from-{}'.format(upgrade),
            clone=upgrade,
            env={
                'GIT_CINNABAR_LOG': 'reexec:3',
                'UPGRADE_FROM': upgrade,
            },
            hg='5.4.2.py3',
        )

    for git in ('1.8.5', '2.7.4'):
        TestTask(
            git=git,
            env={'GIT_OLD_VERSION': '1'}
        )

    for hg in SOME_MERCURIAL_VERSIONS:
        if hg != MERCURIAL_VERSION:
            do_hg_version(hg)

    TestTask(
        task_env='linux',
        variant='asan',
    )
    TestTask(
        task_env='linux',
        variant='asan',
        extra_desc='experiments',
        env={
            'GIT_CINNABAR_EXPERIMENTS': 'true',
        },
    )

    for env in ('linux', 'mingw64', 'osx'):
        # Can't spawn osx workers from pull requests.
        if env.startswith('osx') and not TC_IS_PUSH:
            continue

        TestTask(
            task_env=env,
            variant='coverage' if env == 'linux' else None,
            short_desc='graft tests',
            env={
                'GRAFT': '1',
            },
        )

    TestTask(
        variant='old',
        env={
            'GIT_CINNABAR_OLD_HELPER': '1',
        },
        git='2.30.0'
    )

    TestTask(
        variant='old',
        short_desc='graft tests',
        env={
            'GIT_CINNABAR_OLD_HELPER': '1',
            'GRAFT': '1',
        },
        git='2.30.0'
    )

    rev = old_compatible_python()

    TestTask(
        commit=rev,
        clone=rev,
        extra_desc='old python',
        env={
            'GIT_CINNABAR_OLD': '1',
        },
        hg='5.4.2',
    )

    TestTask(
        commit=rev,
        clone=rev,
        short_desc='graft tests',
        extra_desc='old python',
        env={
            'GIT_CINNABAR_OLD': '1',
            'GRAFT': '1',
        },
        hg='5.4.2',
    )

    for env in ('linux', 'mingw64', 'osx'):
        # Can't spawn osx workers from pull requests.
        if env.startswith('osx') and not TC_IS_PUSH:
            continue

        TestTask(
            task_env=env,
            hg='{}.py3'.format(MERCURIAL_VERSION),
        )

        TestTask(
            task_env=env,
            short_desc='graft tests',
            env={
                'GRAFT': '1',
            },
            hg='{}.py3'.format(MERCURIAL_VERSION),
        )

    TestTask(
        extra_desc='experiments',
        env={
            'GIT_CINNABAR_EXPERIMENTS': 'true',
        },
    )

    TestTask(
        variant='coverage',
        short_desc='graft tests',
        extra_desc='experiments',
        env={
            'GIT_CINNABAR_EXPERIMENTS': 'true',
            'GRAFT': '1',
        },
    )

    TestTask(
        extra_desc='experiments',
        env={
            'GIT_CINNABAR_EXPERIMENTS': 'true',
            'GIT_CINNABAR_LOG': 'reexec:3',
        },
        hg='{}.py3'.format(MERCURIAL_VERSION),
    )

    TestTask(
        short_desc='graft tests',
        extra_desc='experiments',
        env={
            'GIT_CINNABAR_EXPERIMENTS': 'true',
            'GIT_CINNABAR_LOG': 'reexec:3',
            'GRAFT': '1',
        },
        hg='{}.py3'.format(MERCURIAL_VERSION),
    )

    for variant in ('coverage', 'old'):
        env = {
            'GIT_CINNABAR_CHECK': 'no-mercurial',
            'GIT_CINNABAR_PYTHON': 'python2.7',
        }
        kwargs = {}
        if variant == 'old':
            env['GIT_CINNABAR_OLD_HELPER'] = '1'
            kwargs['git'] = '2.30.0'
        TestTask(
            variant=variant,
            extra_desc='no-mercurial',
            pre_command=[
                'python2.7 -m virtualenv venv',
                '. venv/bin/activate',
            ],
            command=[
                'deactivate',
                # deactivate removes the git directory from $PATH.
                # Also add the virtualenv bin directory to $PATH for mercurial
                # to be found, but at the end for the system python to still
                # be picked.
                'export PATH=$PWD/git/bin:$PATH:$PWD/venv/bin',
                'make -C repo -f CI/tests.mk',
            ],
            env=env,
            **kwargs,
        )

    for env, variant, check in (
        ('linux', 'coverage', []),
        ('linux', 'coverage', ['no-mercurial']),
        ('linux', 'asan', []),
        ('linux', 'asan', ['no-mercurial']),
        ('osx', None, []),
    ):
        # Can't spawn osx workers from pull requests.
        if env.startswith('osx') and not TC_IS_PUSH:
            continue

        pre_command = []
        if env != 'linux':
            pre_command.append('pip install cram==0.7')

        TestTask(
            task_env=env,
            variant=variant,
            short_desc='cram',
            extra_desc=' '.join(check),
            clone=False,
            command=pre_command + [
                'cram --verbose repo/tests',
            ],
            env={
                'GIT_CINNABAR_CHECK': ','.join(
                    ['no-version-check'] + check),
            },
        )

    for check in ([], ['no-mercurial']):
        TestTask(
            short_desc='cram',
            extra_desc=' '.join(check),
            clone=False,
            command=[
                'cram --verbose repo/tests',
            ],
            env={
                'GIT_CINNABAR_CHECK': ','.join(
                    ['no-version-check'] + check),
                'GIT_CINNABAR_EXPERIMENTS': 'true',
            },
            hg='{}.py3'.format(MERCURIAL_VERSION),
        )


def do_hg_version(hg):
    TestTask(hg=hg)
    cram_hg = [hg]
    try:
        # Don't run cram tests for version < 3.6, which would need
        # different tests because of server-side changes in behavior
        # wrt bookmarks.
        if StrictVersion(hg) < '3.6':
            return
    except ValueError:
        # `hg` is a sha1 for trunk, which means it's >= 3.6
        TestTask(hg='{}.py3'.format(hg))
        cram_hg.append('{}.py3'.format(hg))
    for hg in cram_hg:
        TestTask(
            short_desc='cram',
            clone=False,
            hg=hg,
            command=[
                'cram --verbose repo/tests',
            ],
            env={
                'GIT_CINNABAR_CHECK': 'no-version-check',
            },
        )


@action('more-hg-versions',
        title='More hg versions',
        description='Trigger tests against more mercurial versions')
def more_hg_versions():
    for hg in ALL_MERCURIAL_VERSIONS:
        if hg != MERCURIAL_VERSION and hg not in SOME_MERCURIAL_VERSIONS:
            do_hg_version(hg)


@action('hg-trunk',
        title='Test w/ hg trunk',
        description='Trigger tests against current mercurial trunk')
def hg_trunk():
    import requests
    r = requests.get('https://www.mercurial-scm.org/repo/hg/?cmd=branchmap')
    trunk = None
    for l in r.text.splitlines():
        fields = l.split()
        if fields[0] == 'default':
            trunk = fields[-1]
    if not trunk:
        raise Exception('Cannot find mercurial trunk changeset')
    do_hg_version(trunk)


def main():
    try:
        func = action.by_name[TC_ACTION or 'decision'].func
    except AttributeError:
        raise Exception('Unsupported action: %s', TC_ACTION or 'decision')

    func()

    merge_coverage = []

    if TestTask.coverage and TC_IS_PUSH and TC_BRANCH:
        download_coverage = [
            'curl -o cov-{{{}.id}}.zip -L {{{}.artifact}}'.format(
                task, task)
            for task in TestTask.coverage
        ]
        task = Helper.by_name('linux.coverage')
        download_coverage.append(
            'curl -o gcno-helper.zip -L {{{}.artifacts[1]}}'.format(task))

        merge_coverage.append(
            '(' + '& '.join(download_coverage) + '& wait)',
        )

        for task in TestTask.coverage:
            merge_coverage.extend([
                'unzip -d cov-{{{}.id}} cov-{{{}.id}}.zip .coverage'.format(
                    task, task),
            ])

        merge_coverage.extend([
            'grcov -s repo -t lcov -o repo/coverage.lcov gcno-helper.zip ' +
            ' '.join(
                'cov-{{{}.id}}.zip'.format(task)
                for task in TestTask.coverage),
            'cd repo',
            'coverage combine --append {}'.format(' '.join(
                '../cov-{{{}.id}}/.coverage'.format(task)
                for task in TestTask.coverage)),
            'cd ..',
        ])

    if merge_coverage:
        Task(
            task_env=TaskEnvironment.by_name('linux.codecov'),
            description='upload coverage',
            scopes=['secrets:get:project/git-cinnabar/codecov'],
            command=list(chain(
                Task.checkout(),
                [
                    'set +x',
                    ('export CODECOV_TOKEN=$(curl -sL '
                     'http://taskcluster/api/secrets/v1/secret/project/git-'
                     'cinnabar/codecov | python2.7'
                     ' -c "import json, sys; print(json.load(sys.stdin)'
                     '[\\"secret\\"][\\"token\\"])")'),
                    'set -x',
                ],
                merge_coverage,
                [
                    'cd repo',
                    'codecov --required --name "taskcluster" --commit {}'
                    ' --branch {}'.format(TC_COMMIT, TC_BRANCH),
                ],
            )),
        )

    for t in Task.by_id.values():
        t.submit()

    if not TC_ACTION and 'TC_GROUP_ID' in os.environ:
        actions = {
            'version': 1,
            'actions': [],
            'variables': {
                'e': dict(TC_DATA, decision_id=''),
                'tasks_for': 'action',
            },
        }
        for name, a in action.by_name.items():
            if name != 'decision':
                actions['actions'].append({
                    'kind': 'task',
                    'name': a.name,
                    'title': a.title,
                    'description': a.description,
                    'context': [],
                    'task': a.task,
                })

        with open('actions.json', 'w') as out:
            out.write(json.dumps(actions, indent=True))


if __name__ == '__main__':
    main()
