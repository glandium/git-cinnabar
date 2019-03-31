import hashlib

from tasks import (
    TaskEnvironment,
    bash_command,
)


class OsxCommon(object):
    os = 'macos'
    cpu = 'x86_64'

    def __init__(self, name):
        self.hexdigest = hashlib.sha1(b'0').hexdigest()
        self.name = name

    def prepare_params(self, params):
        assert 'workerType' not in params
        params['provisionerId'] = 'proj-git-cinnabar'
        params['workerType'] = 'osx-{}'.format(self.version).replace('.', '-')
        command = []
        command.append('export PWD=$(pwd)')
        command.append('export ARTIFACTS=$PWD')
        command.append('virtualenv venv')
        command.append('. venv/bin/activate')
        command.extend(params['command'])
        params['command'] = bash_command(*command)
        if self.name == 'build':
            env = params.setdefault('env', {})
            env.setdefault('MACOSX_DEPLOYMENT_TARGET', '10.6')
            env.setdefault('CC', 'clang')
        return params


class Osx10_10(OsxCommon, metaclass=TaskEnvironment):
    PREFIX = 'osx10_10'
    version = '10.10'


class Osx10_11(OsxCommon, metaclass=TaskEnvironment):
    PREFIX = 'osx10_11'
    version = '10.11'
