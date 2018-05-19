from __future__ import print_function

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
    rawBytes = uuid.uuid4().bytes
    # Ensure base64-encoded bytes start with [A-Za-f]
    first = ord(rawBytes[0])
    if first >= 0xd0:
        rawBytes = chr(first & 0x7f) + rawBytes[1:]
    return base64.urlsafe_b64encode(rawBytes)[:-2]  # Drop '==' padding


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


task_group_id = os.environ.get('TASK_ID') or slugid()
now = datetime.utcnow()


def index_env(idx):
    return 'INDEX_{}'.format(
        idx.replace('.', '_').replace('-', '_').upper()
    )


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
        elif (GITHUB_BASE_USER != GITHUB_HEAD_USER or
                GITHUB_BASE_REPO_NAME != GITHUB_HEAD_REPO_NAME):
            result = self._try_key('github.{}.{}.{}'.format(
                GITHUB_HEAD_USER, GITHUB_HEAD_REPO_NAME, key))
        if not result:
            result = self._try_key('github.{}.{}.{}'.format(
                GITHUB_BASE_USER, GITHUB_BASE_REPO_NAME, key))
        if not result:
            result = slugid()
        self[key] = result
        return result

    def _try_key(self, key, create=False):
        if not self.requests:
            return
        response = self.requests.get(PROXY_INDEX_URL.format(key))
        if response.status_code >= 400:
            # Consume content before returning, so that the connection
            # can be reused.
            response.content
        else:
            data = response.json()
            try:
                expires = datetime.strptime(data['expires'].rstrip('Z'),
                                            '%Y-%m-%dT%H:%M:%S.%f')
            except (KeyError, ValueError):
                expires = now
            # Only consider tasks that aren't expired or won't expire
            # within the hour.
            if expires >= now + 3600:
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
    def checkout(repo=None, commit=None):
        repo = repo or GITHUB_HEAD_REPO_URL
        commit = commit or GITHUB_HEAD_SHA
        return [
            'git clone -n {} repo'.format(repo),
            'git -c advice.detachedHead=false -C repo checkout {}'.format(
                commit),
        ]

    def __init__(self, **kwargs):
        task_env = kwargs.pop('task_env', None)
        kwargs = self.normalize_params(kwargs)
        if task_env:
            kwargs = task_env.prepare_params(kwargs)
        index = kwargs.get('index')
        if index:
            self.id = Task.by_index[index]
        else:
            self.id = slugid()

        task = {
            'created': now.format(),
            'deadline': (now + 3600).format(),
            'retries': 0,
            'provisionerId': 'aws-provisioner-v1',
            'workerType': 'github-worker',
            'schedulerId': 'taskcluster-github',
            'taskGroupId': task_group_id,
            'metadata': {
                'owner': GITHUB_HEAD_USER_EMAIL,
                'source': GITHUB_HEAD_REPO_URL,
            },
            'payload': {
                'maxRunTime': 1800,
            },
        }
        kwargs.setdefault('expireIn', '4 weeks')
        dependencies = [task_group_id]
        self.artifacts = []

        for k, v in kwargs.iteritems():
            if k in ('provisionerId', 'workerType'):
                task[k] = v
            elif k == 'description':
                task['metadata'][k] = task['metadata']['name'] = v
            elif k == 'index':
                if GITHUB_EVENT == 'push':
                    task['routes'] = ['index.github.{}.{}.{}'.format(
                        GITHUB_HEAD_USER, GITHUB_HEAD_REPO_NAME, v)]
            elif k == 'expireIn':
                value = v.split()
                if len(value) == 1:
                    value, multiplier = value, 1
                elif len(value) == 2:
                    value, unit = value
                    value = long(value)
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
                task['expires'] = (now + value * multiplier).format()
            elif k == 'command':
                resolver = Task.Resolver()
                task['payload']['command'] = [
                    resolver.format(a)
                    for a in v
                ]
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
                urls = [
                    ARTIFACT_URL.format(self.id, a)
                    for a in artifacts
                ]
                if kwargs.get('workerType') in ('dummy-worker-packet',
                                                'win2012r2'):
                    artifacts = [
                        a.update(name=name) or a
                        for name, a in artifacts.iteritems()
                    ]
                task['payload']['artifacts'] = artifacts
                if len(artifacts) > 1:
                    self.artifacts = urls
                else:
                    self.artifact = urls[0]
                    self.artifacts = [self.artifact]
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
                    for ext in ('rar', 'tar.bz2', 'tar.gz', 'zip'):
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
            elif k == 'dind':
                features = task['payload'].setdefault('features', {})
                features['dind'] = bool(v)
            else:
                raise Exception("Don't know how to handle {}".format(k))
        task['dependencies'] = sorted(dependencies)
        self.task = task
        Task.by_id[self.id] = self

    def __str__(self):
        return self.id

    def submit(self):
        if isinstance(self.id, Index.Existing):
            return
        print('Submitting task "{}":'.format(self.id))
        print(json.dumps(self.task, indent=4, sort_keys=True))
        if 'TASKCLUSTER_PROXY' not in os.environ:
            return
        url = 'http://taskcluster/queue/v1/task/{}'.format(self.id)
        res = session.put(url, data=json.dumps(self.task))
        try:
            res.raise_for_status()
        except Exception:
            print(res.headers)
            print(res.content)
            raise
        print(res.json())


def bash_command(*commands):
    return ['bash', '-c', '-x', '-e', '; '.join(commands)]
