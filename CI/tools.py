import hashlib
import os

from tasks import (
    Task,
    TaskEnvironment,
    Tool,
    parse_version,
)
from util import build_commit
from docker import DockerImage
import msys


MERCURIAL_VERSION = '5.9.1'
GIT_VERSION = '2.33.1'

ALL_MERCURIAL_VERSIONS = (
    '1.9.3', '2.0.2', '2.1.2', '2.2.3', '2.3.2', '2.4.2', '2.5.4',
    '2.6.3', '2.7.2', '2.8.2', '2.9.1', '3.0.1', '3.1.2', '3.2.4',
    '3.3.3', '3.4.2', '3.5.2', '3.6.3', '3.7.3', '3.8.4', '3.9.2',
    '4.0.2', '4.1.3', '4.2.2', '4.3.3', '4.4.2', '4.5.3', '4.6.2',
    '4.7.2', '4.8.2', '4.9.1', '5.0.2', '5.1.2', '5.2.2', '5.3.2',
    '5.4.2', '5.5.2', '5.6.1', '5.7.1', '5.8.1', '5.9.1',
)

SOME_MERCURIAL_VERSIONS = (
    '1.9.3', '2.5.4', '3.4.2',
)

assert MERCURIAL_VERSION in ALL_MERCURIAL_VERSIONS
assert all(v in ALL_MERCURIAL_VERSIONS for v in SOME_MERCURIAL_VERSIONS)


def nproc(env):
    if env.os == 'macos':
        return 'sysctl -n hw.physicalcpu'
    return 'nproc --all'


class Git(Task, metaclass=Tool):
    PREFIX = "git"

    def __init__(self, os_and_version):
        (os, version) = os_and_version.split('.', 1)
        if os.startswith('osx'):
            build_image = TaskEnvironment.by_name('osx.build')
        else:
            build_image = DockerImage.by_name('build')
        if os == 'linux' or os.startswith('osx'):
            h = hashlib.sha1(build_image.hexdigest.encode())
            h.update(b'v3' if version == GIT_VERSION else b'v2')
            if os == 'linux':
                description = 'git v{}'.format(version)
            else:
                env = build_image
                description = 'git v{} {} {}'.format(version, env.os, env.cpu)
            Task.__init__(
                self,
                task_env=build_image,
                description=description,
                index='{}.git.v{}'.format(h.hexdigest(), version),
                expireIn='26 weeks',
                command=Task.checkout(
                    'git://git.kernel.org/pub/scm/git/git.git',
                    'v{}'.format(version),
                    dest='git',
                ) + Task.checkout() + ([
                    'patch -d git -p1 < repo/CI/git-transport-disconnect.diff',
                ] if version == GIT_VERSION else []) + [
                    'make -C git -j$({}) install prefix=/ NO_GETTEXT=1'
                    ' NO_OPENSSL=1 NO_TCLTK=1 DESTDIR=$PWD/git'.format(
                        nproc(build_image)),
                    'tar -Jcf $ARTIFACTS/git-{}.tar.xz git'
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
                    'curl -L https://github.com/git-for-windows/git/releases/'
                    'download/v{}/Git-{}-{}-bit.tar.bz2 | '
                    'tar -C git -jx {}/libexec/git-core/git-http-backend.exe'
                    .format(version, min_ver, msys.bits(env.cpu),
                            msys.mingw(env.cpu).lower()),
                    'tar -jcf $ARTIFACTS/git-{}.tar.bz2 git'.format(
                        raw_version),
                ],
                artifact='git-{}.tar.bz2'.format(raw_version),
            )

    @classmethod
    def install(cls, name):
        url = '{{{}.artifact}}'.format(cls.by_name(name))
        if name.startswith('linux.'):
            return [
                'curl -L {} | tar -Jxf -'.format(url),
                'export PATH=$PWD/git/bin:$PATH',
                'export GIT_EXEC_PATH=$PWD/git/libexec/git-core',
                'export GIT_TEMPLATE_DIR=$PWD/git/share/git-core/templates',
            ]
        else:
            return [
                'curl -L {} -o git.tar.bz2'.format(url),
                'tar -jxf git.tar.bz2',
            ]


class Hg(Task, metaclass=Tool):
    PREFIX = "hg"

    def __init__(self, os_and_version):
        (os, version) = os_and_version.split('.', 1)
        (version, suffix, _) = version.partition('.py3')
        if suffix:
            python = 'python3'
        else:
            python = 'python2.7'
        env = TaskEnvironment.by_name('{}.build'.format(os))
        kwargs = {}

        if len(version) == 40:
            # Assume it's a sha1
            pretty_version = 'r{}{}'.format(version, suffix)
            artifact_version = 'unknown'
            expire = '2 weeks'
        else:
            pretty_version = 'v{}{}'.format(version, suffix)
            artifact_version = version
            expire = '26 weeks'
        desc = 'hg {}'.format(pretty_version)
        if os == 'linux':
            platform_tag = 'linux_x86_64'
            if python == 'python3':
                python_tag = 'cp35'
                abi_tag = 'cp35m'
            else:
                python_tag = 'cp27'
                abi_tag = 'cp27mu'
        else:
            desc = '{} {} {}'.format(desc, env.os, env.cpu)
            if os.startswith('osx'):
                platform_tag = 'macosx_{}_x86_64'.format(
                    env.os_version.replace('.', '_'))
                if python == 'python3':
                    python_tag = 'cp39'
                    abi_tag = 'cp39'
                else:
                    python_tag = 'cp27'
                    abi_tag = 'cp27m'
                kwargs.setdefault('env', {}).setdefault(
                    'MACOSX_DEPLOYMENT_TARGET', env.os_version)
            else:
                if python == 'python3':
                    platform_tag = 'mingw_x86_64'
                    python_tag = 'cp39'
                    abi_tag = 'cp39'
                else:
                    platform_tag = 'mingw'
                    python_tag = 'cp27'
                    abi_tag = 'cp27m'

        artifact = 'mercurial-{{}}-{}-{}-{}.whl'.format(
            python_tag,
            abi_tag,
            platform_tag,
        )

        pre_command = []
        if len(version) == 40:
            pre_command.extend(
                self.install('{}.{}'.format(os, MERCURIAL_VERSION)))
            pre_command.extend([
                'hg clone https://www.mercurial-scm.org/repo/hg'
                ' -r {} mercurial-{}'.format(version, version),
                'rm -rf hg/.hg',
                'echo tag: unknown > hg/.hg_archival.txt',
            ])
        # 2.6.2 is the first version available on pypi
        elif parse_version('2.6.2') <= parse_version(version):
            # Always download with python2.7 because pip download does more
            # than download, and one of the things it does, namely requirements
            # validation, breaks on Windows with python3 < 3.7 (because
            # mercurial declares it's not compatible with those).
            pre_command.append(
                'python2.7 -m pip download --no-binary mercurial --no-deps'
                ' --progress-bar off mercurial=={}'.format(version))
        else:
            url = 'https://mercurial-scm.org/release/mercurial-{}.tar.gz'
            pre_command.append(
                'curl -sLO {}'.format(url.format(version)))

        if len(version) != 40:
            pre_command.append(
                'tar -zxf mercurial-{}.tar.gz'.format(version))

        h = hashlib.sha1(env.hexdigest.encode())
        h.update(artifact.encode())
        h.update(b'v2' if os.startswith('mingw') else b'v1')

        Task.__init__(
            self,
            task_env=env,
            description=desc,
            index='{}.hg.{}'.format(h.hexdigest(), pretty_version),
            expireIn=expire,
            command=pre_command + [
                # pyproject.toml enables PEP 517, which can't be disabled.
                # pip wheel doesn't accept --build-option when PEP 517 is
                # enabled. --build-option is necessary on msys2 because
                # of problems with the bdist-dir otherwise.
                'rm -f mercurial-{}/pyproject.toml'.format(version),
                '{} -m pip wheel -v --build-option -b --build-option'
                ' $PWD/wheel -w $ARTIFACTS ./mercurial-{}'.format(
                    python,
                    version),
            ],
            artifact=artifact.format(artifact_version),
            **kwargs
        )

    @classmethod
    def install(cls, name):
        hg = cls.by_name(name)
        if name.endswith('.py3'):
            python = 'python3'
        else:
            python = 'python2.7'
        filename = os.path.basename(hg.artifacts[0])
        return [
            'curl -L {{{}.artifact}} -o {}'.format(hg, filename),
            '{} -m pip install {}'.format(python, filename)
        ]


def install_rust(version='1.56.0', target='x86_64-unknown-linux-gnu'):
    rustup_opts = '-y --default-toolchain none'
    cargo_dir = '$HOME/.cargo/bin/'
    rustup = cargo_dir + 'rustup'
    if 'windows' in target:
        cpu, _, __ = target.partition('-')
        rust_install = [
            'curl -o rustup-init.exe https://win.rustup.rs/{cpu}',
            './rustup-init.exe {rustup_opts}',
            '{rustup} set default-host {target}',
        ]
    else:
        rust_install = [
            'curl -o rustup.sh https://sh.rustup.rs',
            'sh rustup.sh {rustup_opts}',
        ]
    rust_install += [
        '{rustup} install {version} --profile minimal',
        '{rustup} default {version}',
        'PATH={cargo_dir}:$PATH',
        '{rustup} target add {target}',
    ]
    if 'windows' in target:
        rust_install += [
            '{rustup} component remove rust-mingw',
        ]
    l = locals()
    return [r.format(**l) for r in rust_install]


class Build(Task, metaclass=Tool):
    PREFIX = 'build'

    def __init__(self, os_and_variant):
        os, variant = (os_and_variant.split('.', 1) + [''])[:2]
        if os.startswith('osx'):
            os = 'osx'
        env = TaskEnvironment.by_name(
            '{}.build'.format(os.replace('arm64-linux', 'linux')))

        artifact = 'git-cinnabar'
        if os.startswith('mingw'):
            artifact += '.exe'
        artifacts = [artifact]

        def prefix(p, s):
            return p + s if s else s

        hash = None
        head = None
        desc_variant = variant
        extra_commands = []
        environ = {}
        cargo_flags = ['-vv', '--release']
        cargo_features = []
        rust_version = None
        if variant == 'asan':
            if os.startswith('osx'):
                opt = '-O2'
            else:
                opt = '-Og'
            environ['TARGET_CFLAGS'] = ' '.join([
                opt,
                '-g',
                '-fsanitize=address',
                '-fno-omit-frame-pointer',
                '-fPIC',
            ])
            environ['RUSTFLAGS'] = ' '.join([
                '-Zsanitizer=address',
                '-Copt-level=1',
                '-Cforce-frame-pointers=yes',
            ])
        elif variant == 'coverage':
            environ['TARGET_CFLAGS'] = ' '.join([
                '-coverage',
                '-fPIC',
            ])
            artifacts += ['coverage.zip']
            extra_commands = [
                '(cd repo && zip $ARTIFACTS/coverage.zip'
                ' $(find . -name "*.gcno" -not -name "build_script*"))',
            ]
            environ['RUSTFLAGS'] = ' '.join([
                '-Zprofile',
                '-Ccodegen-units=1',
                '-Cinline-threshold=0',
            ])
            # Build without --release
            cargo_flags.remove('--release')
            environ['CARGO_INCREMENTAL'] = '0'
        elif variant.startswith('old:'):
            head = variant[4:]
            hash = build_commit(head)
            variant = ''
        elif variant.startswith('rust-'):
            rust_version = variant[5:]
        elif variant:
            raise Exception('Unknown variant: {}'.format(variant))

        if os in ('linux', 'arm64-linux'):
            environ['CC'] = 'clang-12'
            cargo_features.append('curl-compat')

        if os.startswith('mingw'):
            cpu = msys.msys_cpu(env.cpu)
            rust_target = "{}-pc-windows-gnu".format(cpu)
            # Statically link libcurl on Windows.
            # This leaves it to curl-sys build scripts to deal with building
            # libcurl, instead of us.
            cargo_features.extend([
                'curl-sys/ssl',
                'curl-sys/static-curl',
                'curl-sys/static-ssl',
            ])
        elif os.startswith('osx'):
            rust_target = 'x86_64-apple-darwin'
        elif os.startswith('arm64-osx'):
            rust_target = 'aarch64-apple-darwin'
        elif os == 'linux':
            rust_target = 'x86_64-unknown-linux-gnu'
        elif os == 'arm64-linux':
            rust_target = 'aarch64-unknown-linux-gnu'
            environ['PKG_CONFIG_aarch64_unknown_linux_gnu'] = \
                '/usr/bin/aarch64-linux-gnu-pkg-config'
            environ['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER'] = \
                environ['CC']
            environ['CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS'] = \
                '-C link-arg=--target=aarch64-unknown-linux-gnu'
        if variant in ('coverage', 'asan'):
            rust_install = install_rust('nightly-2021-09-05', rust_target)
        elif rust_version:
            rust_install = install_rust(rust_version, target=rust_target)
        else:
            rust_install = install_rust(target=rust_target)
        cargo_flags.extend(['--target', rust_target])
        if cargo_features:
            cargo_flags.extend(['--features', ','.join(cargo_features)])

        hash = hash or build_commit()

        if os.startswith('osx'):
            environ.setdefault(
                'MACOSX_DEPLOYMENT_TARGET', '10.7')

        cpu = 'arm64' if os == 'arm64-linux' else env.cpu
        Task.__init__(
            self,
            task_env=env,
            description='build {} {}{}'.format(
                env.os, cpu, prefix(' ', desc_variant)),
            index='build.{}.{}.{}{}'.format(
                hash, env.os, cpu, prefix('.', variant)),
            expireIn='26 weeks',
            command=Task.checkout(commit=head) + rust_install + [
                '(cd repo ; cargo build {})'.format(' '.join(cargo_flags)),
                'mv repo/target/{}/{}/{} $ARTIFACTS/'.format(
                    rust_target,
                    'release' if '--release' in cargo_flags else 'debug',
                    artifact),
            ] + extra_commands,
            artifacts=artifacts,
            env=environ,
        )

    @classmethod
    def install(cls, name):
        build = cls.by_name(name)
        filename = os.path.basename(build.artifacts[0])
        return [
            'curl --compressed -o repo/{} -L {{{}.artifacts[0]}}'.format(
                filename, build),
            'chmod +x repo/{}'.format(filename),
            'ln -s $PWD/repo/{} $PWD/repo/git-remote-hg'.format(filename),
        ]
