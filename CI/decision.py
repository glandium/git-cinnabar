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
    Build,
    install_rust,
    Git,
    Hg,
    nproc,
)
from variables import *  # noqa: F403


def git_rev_parse(committish):
    from cinnabar.git import Git
    from cinnabar.util import one
    return one(Git.iter('rev-parse', committish,
                        cwd=os.path.join(BASE_DIR, '..'))).decode()


UPGRADE_FROM = ()  # ('0.5.0',)


class TestTask(Task):
    coverage = []

    def __init__(self, **kwargs):
        git = kwargs.pop('git', GIT_VERSION)
        hg = kwargs.pop('hg', MERCURIAL_VERSION)
        commit = kwargs.pop('commit', None)
        task_env = kwargs.pop('task_env', 'linux')
        variant = kwargs.pop('variant', None)
        build = kwargs.pop('build', None)
        clone = kwargs.pop('clone', TC_COMMIT)
        desc = kwargs.pop('description', None)
        short_desc = kwargs.pop('short_desc', 'test')
        extra_desc = kwargs.pop('extra_desc', None)
        pre_command = kwargs.pop('pre_command', None)
        if build is None:
            build = '{}.{}'.format(task_env, variant) if variant else task_env
            build = Build.install(build)
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
        command.extend(build)
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
                command.append(
                    'git -C repo -c core.autocrlf=input checkout {} CI'
                    .format(TC_COMMIT))
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
                'cd repo',
                'zip $ARTIFACTS/coverage.zip .coverage'
                ' $(find . -name "*.gcda")',
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
                download = Build.install('linux')
            else:
                download = Build.install('linux.old:{}'.format(version))
            expireIn = '26 weeks'
        elif parse_version(version) < parse_version('0.6.0'):
            download = ['repo/git-cinnabar download']
        else:
            download = ['repo/download.py']
        kwargs = {}
        if parse_version(version) < parse_version('0.5.7'):
            kwargs['git'] = '2.30.2'
        if REPO == DEFAULT_REPO:
            index = 'bundle.{}'.format(sha1)
        else:
            index = 'bundle.{}.{}'.format(hashlib.sha1(REPO).hexdigest(), sha1)
        TestTask.__init__(
            self,
            hg=MERCURIAL_VERSION,
            description='clone w/ {}'.format(version),
            index=index,
            expireIn=expireIn,
            build=download,
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
            'PATH=$PWD/repo:$PATH',
            '(cd repo &&'
            ' nosetests3 --all-modules --with-coverage --cover-tests tests)',
            '(cd repo && flake8 --ignore E402,F405'
            ' $(git ls-files \\*\\*.py | grep -v ^bootstrap/))',
            '(cd repo && flake8 --ignore E402,F405,F821'
            ' $(git ls-files bootstrap/\\*\\*.py))',
        ],
    )

    for env in ('linux', 'mingw64', 'osx'):
        # Can't spawn osx workers from pull requests.
        if env.startswith('osx') and not TC_IS_PUSH:
            continue

        TestTask(
            task_env=env,
            variant='coverage' if env == 'linux' else None,
        )

        task_env = TaskEnvironment.by_name('{}.test'.format(env))
        Task(
            task_env=task_env,
            description='download build {} {}'.format(task_env.os,
                                                      task_env.cpu),
            command=list(chain(
                Git.install('{}.{}'.format(env, GIT_VERSION)),
                Hg.install('{}.{}'.format(env, MERCURIAL_VERSION)),
                Task.checkout(),
                [
                    '(cd repo ; ./download.py)',
                ],
            )),
            dependencies=[
                Build.by_name(env),
            ],
        )

    # Because nothing is using the x86 windows build, we need to manually
    # touch it.
    Build.by_name('mingw32')
    # Same for arm64 mac
    if TC_IS_PUSH:
        Build.by_name('arm64-osx')
    Build.by_name('arm64-linux')

    # Test build with the MSRV.
    Build.by_name('linux.rust-1.51.0')

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

    for env, variant in (
        ('linux', 'coverage'),
        ('linux', 'asan'),
        ('osx', None),
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
            clone=False,
            command=pre_command + [
                'cram --verbose repo/tests',
            ],
            env={
                'GIT_CINNABAR_CHECK': 'no-version-check',
            },
        )

    for cargo_cmd in ('test', 'clippy', 'fmt'):
        for env in ('linux', 'mingw64', 'osx'):
            # Can't spawn osx workers from pull requests.
            if env.startswith('osx') and not TC_IS_PUSH:
                continue

            task_env = TaskEnvironment.by_name('{}.build'.format(env))
            desc = 'cargo {}'.format(cargo_cmd)
            if env != 'linux':
                desc = ' '.join((desc, task_env.os, task_env.cpu))
            Task(
                task_env=task_env,
                description=desc,
                command=list(chain(
                    install_rust(target={
                        'linux': 'x86_64-unknown-linux-gnu',
                        'mingw64': 'x86_64-pc-windows-gnu',
                        'osx': 'x86_64-apple-darwin',
                    }[env]),
                    {
                        'clippy': ['rustup component add clippy'],
                        'fmt': ['rustup component add rustfmt'],
                    }.get(cargo_cmd, []),
                    Task.checkout(),
                    ['git -C repo submodule update --init']
                    if cargo_cmd != 'fmt' else [],
                    [
                        '(cd repo ; cargo {})'.format({
                            'clippy': 'clippy -- -D warnings',
                            'fmt': 'fmt -- --check',
                        }.get(cargo_cmd, cargo_cmd)),
                    ],
                )),
            )
            if cargo_cmd == 'fmt':
                break


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
        task = Build.by_name('linux.coverage')
        download_coverage.append(
            'curl -o gcno-build.zip -L {{{}.artifacts[1]}}'.format(task))

        merge_coverage.append(
            '(' + '& '.join(download_coverage) + '& wait)',
        )

        for task in TestTask.coverage:
            merge_coverage.extend([
                'unzip -d cov-{{{}.id}} cov-{{{}.id}}.zip .coverage'.format(
                    task, task),
            ])

        merge_coverage.extend([
            'grcov -s repo -t lcov -o repo/coverage.lcov gcno-build.zip ' +
            ' '.join(
                'cov-{{{}.id}}.zip'.format(task)
                for task in TestTask.coverage),
            'cd repo',
            '(echo "[paths]"; echo "source ="; echo "  $PWD/cinnabar";'
            ' echo "  /git-cinnabar::cinnabar") > .coveragerc',
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
