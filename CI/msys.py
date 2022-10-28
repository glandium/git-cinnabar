import hashlib
import os
import re

from tasks import (
    Task,
    TaskEnvironment,
    Tool,
    bash_command,
)
from docker import DockerImage


CPUS = ('x86', 'x86_64')
MSYS_VERSION = '20161025'


def mingw(cpu):
    return {
        'x86': 'MINGW32',
        'x86_64': 'MINGW64',
    }.get(cpu)


def msys(cpu):
    return {
        'x86': 'msys32',
        'x86_64': 'msys64',
    }.get(cpu)


def msys_cpu(cpu):
    return {
        'x86': 'i686',
    }.get(cpu, cpu)


def bits(cpu):
    return {
        'x86': '32',
        'x86_64': '64',
    }.get(cpu)


class MsysCommon(object):
    os = 'windows'

    def prepare_params(self, params):
        assert 'workerType' not in params
        params['workerType'] = 'win2012r2'
        assert 'mounts' not in params
        params['mounts'] = [self]
        params.setdefault('env', {})['MSYSTEM'] = mingw(self.cpu)

        command = []
        command.append('set HOME=%CD%')
        command.append('set ARTIFACTS=%CD%')
        for path in (mingw(self.cpu), 'usr'):
            command.append('set PATH=%CD%\\{}\\{}\\bin;%PATH%'
                           .format(msys(self.cpu), path))
        command.append(
            'set PATH=%CD%\\git\\{}\\bin;%PATH%'.format(mingw(self.cpu)))
        if self.PREFIX != 'msys':
            command.append('bash -c -x "{}"'.format('; '.join((
                'for postinst in /etc/post-install/*.post',
                'do test -e $postinst && . $postinst',
                'done',
            ))))
        command.append(' '.join(
            _quote(arg) for arg in bash_command(*params['command'])))
        params['command'] = command
        return params

    @property
    def index(self):
        return '.'.join(('env', self.PREFIX, self.cpu, self.hexdigest))


class MsysBase(MsysCommon, Task, metaclass=Tool):
    PREFIX = "msys"

    def __init__(self, cpu):
        assert cpu in CPUS
        crts = (
            '{msys}/usr/ssl/cert.pem '
            '{msys}/usr/ssl/certs/ca-bundle.crt '
            '{msys}/usr/ssl/certs/ca-bundle.trust.crt'
        )
        crts64 = crts.format(msys='msys64')
        crts = crts.format(msys=msys(cpu))
        _create_command = [
            'curl -L http://mirrors.huaweicloud.com/repository/msys2'
            '/distrib/{cpu}'
            '/msys2-base-{cpu}-{version}.tar.xz | xz -cd > msys2.tar'
            .format(cpu=msys_cpu(cpu), version=MSYS_VERSION),
            'tar --delete -f msys2.tar {}'.format(crts),
            'curl -L https://repo.msys2.org/distrib/x86_64/'
            'msys2-base-x86_64-20220128.tar.xz | tar -Jx {}'.format(crts64),
        ]
        if crts64 != crts:
            _create_command.append('mv msys64 msys32')
        _create_command += [
            'tar -rf msys2.tar {}'.format(crts),
            'bzip2 -c msys2.tar > $ARTIFACTS/msys2.tar.bz2',
        ]
        h = hashlib.sha1(';'.join(_create_command).encode())
        self.hexdigest = h.hexdigest()
        self.cpu = cpu

        Task.__init__(
            self,
            task_env=DockerImage.by_name('base'),
            description='msys2 image: base {}'.format(cpu),
            index=self.index,
            expireIn='26 weeks',
            command=_create_command,
            artifact='msys2.tar.bz2',
        )


class MsysEnvironment(MsysCommon):
    def __init__(self, name):
        cpu = self.cpu
        create_commands = [
            'pacman-key --init',
            'pacman-key --populate msys2',
            'sed -i s,://repo.msys2.org/,'
            '://mirrors.huaweicloud.com/repository/msys2/,'
            ' /etc/pacman.d/mirrorlist.*',
            'pacman --noconfirm -Sy tar {}'.format(
                ' '.join(self.packages(name))),
            '[ -f /{mingw}/ssl/cert.pem ] &&'
            ' cp /usr/ssl/cert.pem /{mingw}/ssl'.format(mingw=mingw(cpu)),
            '[ -d /{mingw}/ssl/certs ] &&'
            ' cp /usr/ssl/certs/* /{mingw}/ssl/certs'.format(mingw=mingw(cpu)),
            'rm -rf /var/cache/pacman/pkg',
            'python2.7 -m pip install pip==20.3.4 wheel==0.37.0 --upgrade',
            'python3 -m pip install pip==20.3.4 wheel==0.37.0 --upgrade',
            'mv {}/{}/bin/{{{{mingw32-,}}}}make.exe'.format(msys(cpu),
                                                            mingw(cpu)),
            'tar -jcf msys2.tar.bz2 --hard-dereference {}'.format(msys(cpu)),
        ]

        if name == 'build':
            # https://github.com/msys2/MINGW-packages/issues/5155
            url = ('https://raw.githubusercontent.com/msys2/MINGW-packages/'
                   '8a162525a7d6f4a0ac2724db2e21c96eae1ba33f/'
                   'mingw-w64-python2/2030-fix-msvc9-import.patch')
            create_commands[-1:-1] = [
                'curl -sLO {}'.format(url)
            ]
            for pyver in ('2.7', '3.5'):
                path = '/{}/lib/python{}/distutils/msvc9compiler.py'.format(
                    mingw(cpu), pyver)
                create_commands[-1:-1] = [
                    'patch {} < {}'.format(path, os.path.basename(url)),
                ]

        env = MsysBase.by_name(cpu)

        h = hashlib.sha1(env.hexdigest.encode())
        h.update(';'.join(create_commands).encode())
        self.hexdigest = h.hexdigest()

        Task.__init__(
            self,
            task_env=env,
            description='msys2 image: {} {}'.format(name, cpu),
            index=self.index,
            expireIn='26 weeks',
            command=create_commands,
            artifact='msys2.tar.bz2',
        )

    def packages(self, name):
        def mingw_packages(pkgs):
            return [
                'mingw-w64-{}-{}'.format(msys_cpu(self.cpu), pkg)
                for pkg in pkgs
            ]

        packages = mingw_packages([
            'curl',
            'make',
            'pcre',
            'python2',
            'python2-pip',
            'python3',
            'python3-pip',
        ])

        if name == 'build':
            return packages + mingw_packages([
                'gcc',
                'perl',
            ]) + [
                'patch',
            ]
        elif name == 'test':
            return packages + [
                'diffutils',
                'git',
            ]
        raise Exception('Unknown name: {}'.format(name))


class Msys32Environment(MsysEnvironment, Task, metaclass=TaskEnvironment):
    PREFIX = 'mingw32'
    cpu = 'x86'
    __init__ = MsysEnvironment.__init__


class Msys64Environment(MsysEnvironment, Task, metaclass=TaskEnvironment):
    PREFIX = 'mingw64'
    cpu = 'x86_64'
    __init__ = MsysEnvironment.__init__


SHELL_QUOTE_RE = re.compile(r'[\\\t\r\n \'\"#<>&|`~(){}$;\*\?]')


def _quote(s):
    if s and not SHELL_QUOTE_RE.search(s):
        return s
    for c in '^&\\<>|':
        s = s.replace(c, '^' + c)
    return "'{}'".format(s.replace("'", "'\\''"))
