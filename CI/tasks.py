# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import base64
import datetime
import json
import numbers
import os
import requests
import uuid

from collections import OrderedDict
from pkg_resources import parse_version  # noqa: F401
from string import Formatter

from variables import *  # noqa: F403


def slugid():
    rawBytes = bytearray(uuid.uuid4().bytes)
    # Ensure base64-encoded bytes start with [A-Za-f]
    if rawBytes[0] >= 0xd0:
        rawBytes[0] = rawBytes[0] & 0x7f
    result = base64.urlsafe_b64encode(rawBytes)[:-2]  # Drop '==' padding
    return result.decode()


timedelta = datetime.timedelta


class datetime(datetime.datetime):
    def format(self, no_usec=True):
        if no_usec:
            return self.replace(microsecond=0).isoformat() + 'Z'
        if self.microsecond == 0:
            return self.isoformat() + '.000000Z'
        return self.isoformat() + 'Z'

    def __add__(self, other):
        if isinstance(other, numbers.Number):
            other = timedelta(seconds=other)
        d = super(datetime, self).__add__(other)
        return self.combine(d.date(), d.timetz())


task_group_id = (os.environ.get('TC_GROUP_ID') or
                 os.environ.get('TASK_ID') or slugid())
now = datetime.utcnow()


def index_env(idx):
    return 'INDEX_{}'.format(
        idx.replace('.', '_').replace('-', '_').upper()
    )


def expires_soon(expires):
    try:
        expires = datetime.strptime(
            expires.rstrip('Z'), '%Y-%m-%dT%H:%M:%S.%f')
        return expires < now + 3600
    except (KeyError, ValueError):
        return True


def http_get(session, url):
    response = session.get(url)
    if response.status_code >= 400:
        # Consume content before returning, so that the connection
        # can be reused.
        response.content
    else:
        return response.json()


class Index(dict):
    class Existing(str):
        pass

    def __init__(self, requests=requests):
        super(Index, self).__init__()
        self.requests = None if os.environ.get('NO_INDEX') else requests

    def __missing__(self, key):
        result = None
        hint = os.environ.get(index_env(key))
        if hint:
            result = self.Existing(hint)
        elif hint is not None:  # empty environment variable
            pass
        else:
            result = self._try_key('project.git-cinnabar.{}'.format(key))
        if not result:
            result = slugid()
        self[key] = result
        return result

    def _try_key(self, key, create=False):
        if not self.requests:
            return
        data = http_get(self.requests, PROXY_INDEX_URL.format(key))
        if data and not expires_soon(data['expires']):
            result = data.get('taskId')
            print('Found task "{}" for "{}"'.format(result, key))
            return self.Existing(result)

    def search_local_with_prefix(self, prefix):
        matches = [k for k in self.keys() if k.startswith(prefix)]
        if len(matches) > 1:
            raise Exception("Multiple matches for prefix {}".format(prefix))
        if not matches:
            raise Exception("No match for prefix {}".format(prefix))
        return self[matches[0]]


session = requests.Session()


class TaskNamespace(type):
    @classmethod
    def by_name(cls, fqdn):
        env = cls._namespace.get(fqdn)
        if not env:
            n = fqdn.split('.')
            prefix = n[:-1]
            name = n[-1:]
            while prefix:
                kls = cls._namespace.get('.'.join(prefix))
                if isinstance(kls, type):
                    cls._namespace[fqdn] = env = kls('.'.join(name))
                    break
                name.insert(0, prefix.pop())
        return env

    def __new__(cls, name, bases, dic):
        @classmethod
        def by_name(kls, name):
            return cls.by_name('.'.join((kls.PREFIX, name)))
        dic['by_name'] = by_name

        kls = super(TaskNamespace, cls).__new__(cls, name, bases, dic)
        cls._namespace[dic['PREFIX']] = kls
        return kls


class Tool(TaskNamespace):
    _namespace = OrderedDict()


class TaskEnvironment(TaskNamespace):
    _namespace = OrderedDict()


class Task(object):
    by_index = Index(session)
    by_id = OrderedDict()

    class Resolver(Formatter):
        def __init__(self):
            self._used = set()

        def get_value(self, key, args, kwargs):
            task = Task.by_id.get(key)
            if task:
                self._used.add(task)
                return task
            raise KeyError(key)

        def used(self):
            for u in self._used:
                yield u

    @staticmethod
    def normalize_params(params):
        try:
            artifact = params.pop('artifact')
            assert 'artifacts' not in params
            params['artifacts'] = [artifact]
        except KeyError:
            pass
        return params

        try:
            mount = params.pop('mount')
            assert 'mounts' not in params
            params['mounts'] = [mount]
        except KeyError:
            pass

    @staticmethod
    def checkout(repo=None, commit=None, dest='repo'):
        repo = repo or TC_REPO_URL
        commit = commit or TC_COMMIT
        return [
            'git clone -n {} {}'.format(repo, dest),
            'git -c core.autocrlf=input -c advice.detachedHead=false'
            ' -C {} checkout {}'.format(dest, commit),
        ]

    def __init__(self, **kwargs):
        task_env = kwargs.pop('task_env', None)
        kwargs = self.normalize_params(kwargs)
        if task_env:
            kwargs = task_env.prepare_params(kwargs)

        maxRunTime = kwargs.pop('maxRunTime', 1800)
        task = {
            'created': now.format(),
            'deadline': (now + maxRunTime * 5 + 1800).format(),
            'retries': 5,
            'provisionerId': 'proj-git-cinnabar',
            'workerType': 'ci',
            'schedulerId': 'taskcluster-github',
            'taskGroupId': task_group_id,
            'metadata': {
                'owner': '{}@users.noreply.github.com'.format(TC_LOGIN),
                'source': TC_REPO_URL,
            },
            'payload': {
                'maxRunTime': maxRunTime,
            },
        }
        kwargs.setdefault('expireIn', '4 weeks')
        dependencies = [os.environ.get('TASK_ID') or task_group_id]
        artifact_paths = []

        for k, v in kwargs.items():
            if k in ('provisionerId', 'workerType', 'priority'):
                task[k] = v
            elif k == 'description':
                task['metadata'][k] = task['metadata']['name'] = v
            elif k == 'index':
                if TC_IS_PUSH and TC_BRANCH != "try":
                    task['routes'] = [
                        'index.project.git-cinnabar.{}'.format(v)]
            elif k == 'expireIn':
                value = v.split()
                if len(value) == 1:
                    value, multiplier = value, 1
                elif len(value) == 2:
                    value, unit = value
                    value = int(value)
                    unit = unit.rstrip('s')
                    multiplier = 1
                    if unit == 'year':
                        multiplier *= 365
                        unit = 'day'
                    if unit == 'week':
                        multiplier *= 7
                        unit = 'day'
                    if unit == 'day':
                        multiplier *= 24
                        unit = 'hour'
                    if unit == 'hour':
                        multiplier *= 60
                        unit = 'minute'
                    if unit == 'minute':
                        multiplier *= 60
                        unit = 'second'
                    if unit == 'second':
                        unit = ''
                    if unit:
                        raise Exception(
                            "Don't know how to handle {}".format(unit))
                else:
                    raise Exception("Don't know how to handle {}".format(v))
                if not TC_IS_PUSH or TC_BRANCH == "try":
                    if value * multiplier > 4 * 7 * 24 * 60 * 60:
                        value = 4
                        multiplier = 7 * 24 * 60 * 60  # weeks
                task['expires'] = (now + value * multiplier).format()
            elif k == 'command':
                resolver = Task.Resolver()
                task['payload']['command'] = [
                    resolver.format(a)
                    for a in v
                ]
                if kwargs.get('workerType', '').startswith('osx'):
                    task['payload']['command'] = [task['payload']['command']]
                for t in resolver.used():
                    dependencies.append(t.id)

            elif k == 'artifacts':
                artifacts = {
                    'public/{}'.format(os.path.basename(a)): {
                        'path': a,
                        'type': 'file',
                    }
                    for a in v
                }
                artifact_paths.extend(artifacts.keys())
                if kwargs.get('workerType', '').startswith(
                        ('osx', 'win2012r2')):
                    artifacts = [
                        a.update(name=name) or a
                        for name, a in artifacts.items()
                    ]
                task['payload']['artifacts'] = artifacts
            elif k == 'env':
                task['payload'].setdefault('env', {}).update(v)
            elif k == 'image':
                if isinstance(v, Task):
                    v = {
                        'path': 'public/{}'.format(
                            os.path.basename(v.artifact)),
                        'taskId': v.id,
                        'type': 'task-image',
                    }
                    dependencies.append(v['taskId'])
                task['payload']['image'] = v
            elif k == 'scopes':
                task[k] = v
                for s in v:
                    if s.startswith('secrets:'):
                        features = task['payload'].setdefault('features', {})
                        features['taskclusterProxy'] = True
            elif k == 'mounts':
                def file_format(url):
                    for ext in ('rar', 'tar.zst', 'tar.bz2', 'tar.gz', 'zip'):
                        if url.endswith('.{}'.format(ext)):
                            return ext
                    raise Exception(
                        'Unsupported/unknown format for {}'.format(url))

                mounts = task['payload']['mounts'] = []
                for t in v:
                    if isinstance(t, Task):
                        mounts.append({
                            'content': {
                                'artifact': '/'.join(
                                    t.artifact.rsplit('/', 2)[-2:]),
                                'taskId': t.id,
                            },
                            'directory': '.',
                            'format': file_format(t.artifact),
                        })
                        dependencies.append(t.id)
                    else:
                        if not isinstance(t, dict):
                            t = {
                                'url': t,
                                'directory': '.',
                            }
                        mounts.append({
                            'content': {
                                'url': t['url'],
                            },
                            'directory': t['directory'],
                            'format': file_format(t['url']),
                        })
            elif k == 'dependencies':
                for t in v:
                    if hasattr(t, 'index'):
                        env = task['payload'].setdefault('env', {})
                        env[index_env(t.index)] = t.id
                    dependencies.append(t.id)
            elif k == 'dockerSave':
                features = task['payload'].setdefault('features', {})
                features[k] = bool(v)
                artifact_paths.append('public/dockerImage.tar')
            else:
                raise Exception("Don't know how to handle {}".format(k))
        task['dependencies'] = sorted(dependencies)
        index = kwargs.get('index')
        id = None
        if index and all(isinstance(d, Index.Existing)
                         for d in dependencies[1:]):
            id = Task.by_index[index]
        if isinstance(id, Index.Existing):
            data = http_get(
                session, ARTIFACT_URL.format(id, '').rstrip('/')) or {}
            artifacts_expire = [
                expires_soon(a.get('expires'))
                for a in data.get('artifacts', [])
                if a.get('name') in artifact_paths
            ]
            if len(artifact_paths) != len(artifacts_expire) \
                    or any(artifacts_expire):
                print(
                    'Ignore task "{}" because of missing or expiring artifacts'
                    .format(id))
                id = None

        self.id = id or slugid()
        urls = [
            ARTIFACT_URL.format(self.id, a)
            for a in artifact_paths
        ]
        if len(urls) > 1:
            self.artifacts = urls
        elif urls:
            self.artifact = urls[0]
            self.artifacts = [self.artifact]
        else:
            self.artifacts = []
        self.task = task
        Task.by_id.setdefault(self.id, self)

    def __str__(self):
        return self.id

    def submit(self):
        if isinstance(self.id, Index.Existing):
            return
        print('Submitting task "{}":'.format(self.id))
        print(json.dumps(self.task, indent=4, sort_keys=True))
        if 'TC_PROXY' not in os.environ:
            return
        url = f'{PROXY_URL}/api/queue/v1/task/{self.id}'
        res = session.put(url, json=self.task)
        try:
            res.raise_for_status()
        except Exception:
            print(res.headers)
            try:
                print(res.json()['message'])
            except Exception:
                print(res.content)
            raise
        print(res.json())


def bash_command(*commands):
    return ['bash', '-c', '-x', '-e', '; '.join(commands)]


class action(object):
    by_name = OrderedDict()

    template = None

    def __init__(self, name, title=None, description=None):
        assert name not in self.by_name
        self.by_name[name] = self
        self.name = name
        self.title = title
        self.description = description

        if self.template is None:
            import yaml
            with open(os.path.join(os.path.dirname(__file__), '..',
                                   '.taskcluster.yml')) as fh:
                contents = yaml.safe_load(fh)
            task = contents['tasks'][0]['then']['in']
            del task['taskId']
            self.__class__.template = task

        def adjust(s):
            return s.replace('decision', 'action') + ' ({})'.format(title)

        metadata = self.template['metadata']
        self.task = dict(
            self.template,
            payload=dict(self.template['payload'],
                         env=dict(self.template['payload']['env'],
                                  TC_ACTION=name)),
            metadata=dict(metadata,
                          name=adjust(metadata['name']),
                          description=adjust(metadata['description'])))

    def __call__(self, func):
        self.func = func
        return func
