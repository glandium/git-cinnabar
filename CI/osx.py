import hashlib

from tasks import (
    TaskEnvironment,
    bash_command,
)


class OsxCommon(object):
    os = 'macos'
    cpu = 'x86_64'

    def __init__(self, name):
        self.hexdigest = hashlib.sha1(
            self.ITERATION.encode('utf-8')).hexdigest()
        self.name = name

    def prepare_params(self, params):
        assert 'workerType' not in params
        params['provisionerId'] = 'proj-git-cinnabar'
        params['workerType'] = 'osx{}'.format(self.worker_suffix)
        command = []
        command.append('export PWD=$(pwd)')
        command.append('export ARTIFACTS=$PWD')
        command.append('virtualenv venv')
        command.append('. venv/bin/activate')
        command.extend(params['command'])
        params['command'] = bash_command(*command)
        return params


class Osx(OsxCommon, metaclass=TaskEnvironment):
    ITERATION = '1'
    PREFIX = 'osx'
    worker_suffix = ''
    os_version = '10.15'
