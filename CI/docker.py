import hashlib
import os
import sys
import tarfile
import textwrap

from io import BytesIO
from tasks import (
    Task,
    TaskEnvironment,
    bash_command,
)
from variables import (
    ARTIFACT_URL,
    TC_REPO_NAME,
)


def sources_list(snapshot, sections):
    for idx, (archive, dist) in enumerate(sections):
        yield 'deb http://snapshot.debian.org/archive/{}/{} {} main'.format(
            archive,
            snapshot,
            dist,
        )


DOCKER_IMAGES = {
    'base': '''\
        FROM debian:stretch-20190812
        RUN ({}) > /etc/apt/sources.list
        RUN apt-get update -o Acquire::Check-Valid-Until=false
        RUN apt-get install -y --no-install-recommends\\
         bzip2\\
         ca-certificates\\
         curl\\
         python-setuptools\\
         python-pip\\
         python-wheel\\
         python3-setuptools\\
         python3-pip\\
         python3-wheel\\
         unzip\\
         xz-utils\\
         zip\\
         && apt-get clean
        RUN pip install pip==19.2.2 --upgrade --ignore-installed
        '''.format('; '.join('echo ' + l for l in sources_list(
            '20190812T140702Z', (
                ('debian', 'stretch'),
                ('debian', 'stretch-updates'),
                ('debian-security', 'stretch/updates'),
            )))),

    'build': '''\
        FROM base
        RUN apt-get install -y --no-install-recommends\\
         gcc\\
         git\\
         libc6-dev\\
         libcurl4-openssl-dev\\
         make\\
         patch\\
         python-dev\\
         python3-dev\\
         zlib1g-dev\\
         && apt-get clean
        ''',

    'codecov': '''\
        FROM base
        RUN apt-get install -y --no-install-recommends\\
         gcc\\
         git\\
         python-coverage\\
         && apt-get clean
        RUN ln -s /usr/bin/python-coverage /usr/local/bin/coverage\\
         && pip install codecov==2.0.15
        RUN curl -sL {} | tar -C /usr/local/bin -jxf -
        '''.format(
        'https://github.com/mozilla/grcov/releases/download/v0.7.1'
        '/grcov-linux-x86_64.tar.bz2'
    ),

    'test': '''\
        FROM base
        RUN apt-get install -y --no-install-recommends\\
         flake8\\
         make\\
         python-coverage\\
         python-flake8\\
         python3-flake8\\
         python-nose\\
         python3-nose\\
         python-requests\\
         python-virtualenv\\
         && apt-get clean\\
         && pip install cram==0.7
        ''',
}


class HashWriter(object):
    def __init__(self):
        self._h = hashlib.sha1()

    def write(self, buf):
        self._h.update(buf)

    def hexdigest(self):
        return self._h.hexdigest()


class DockerImage(object):
    PREFIX = 'linux'

    def __init__(self, name):
        defn = DOCKER_IMAGES[name]
        defn = textwrap.dedent(defn).splitlines()
        assert defn[0].startswith('FROM ')
        base = defn.pop(0)[5:].strip()
        self.name = name
        if ':' not in base:
            base = self.__class__(base)
        self.base = base
        self.definition = '\n'.join(defn)

    def __str__(self):
        return '{}/{}:{}'.format(
            TC_REPO_NAME,
            self.name,
            self.hexdigest
        )

    tag = property(__str__)

    @property
    def index(self):
        return '.'.join((self.PREFIX, self.name, self.hexdigest))

    @property
    def hexdigest(self):
        h = HashWriter()
        self.send_context_to(h)
        return h.hexdigest()

    def send_context_to(self, fileobj):
        base = str(self.base)
        dockerfile = 'FROM {}\n{}'.format(base, self.definition)
        with tarfile.open(mode='w|', fileobj=fileobj,
                          format=tarfile.GNU_FORMAT) as tar:
            info = tarfile.TarInfo('Dockerfile')
            info.mode = 0o644
            info.type = tarfile.REGTYPE
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            info.mtime = 0
            info.size = len(dockerfile)
            tar.addfile(info, BytesIO(dockerfile.encode()))


class DockerImageTask(DockerImage, Task, metaclass=TaskEnvironment):
    PREFIX = 'linux'
    cpu = 'x86_64'
    os = 'linux'

    def __init__(self, name):
        super(DockerImageTask, self).__init__(name)

        kwargs = {}
        if isinstance(self.base, DockerImage):
            kwargs['dependencies'] = [self.base]
        Task.__init__(
            self,
            task_env=self,
            description='docker image: {}'.format(name),
            index=self.index,
            expireIn='26 weeks',
            image='python:3.7',
            dind=True,
            command=Task.checkout() + [
                'pip install requests-unixsocket zstandard==0.8.1',
                'python repo/CI/docker.py build {}'
                .format(name),
                'python repo/CI/docker.py save {}'
                ' > $ARTIFACTS/image.tar.zst'.format(name),
            ],
            artifact='image.tar.zst',
            **kwargs
        )

    def prepare_params(self, params):
        if 'image' not in params:
            params['image'] = self
        params['command'] = bash_command(*params['command'])
        params.setdefault('env', {})['ARTIFACTS'] = '/tmp'
        if 'artifacts' in params:
            params['artifacts'] = ['{}/{}'.format('/tmp', a)
                                   for a in params['artifacts']]
        return params


if __name__ != '__main__':
    DockerImage = DockerImageTask


def docker_session():
    import requests_unixsocket
    return requests_unixsocket.Session()


def docker_url(path, **kwargs):
    from urllib.parse import (
        quote,
        urlencode,
        urlunparse,
    )

    docker_socket = os.environ.get('DOCKER_SOCKET', '/var/run/docker.sock')
    return urlunparse((
        'http+unix',
        quote(docker_socket, safe=''),
        path,
        '',
        urlencode(kwargs),
        ''))


class CommandHandler(object):
    @staticmethod
    def _valid_stdout():
        if sys.stdout.isatty():
            print('Refusing to send binary data to your terminal.',
                  file=sys.stderr)
            return False
        return True

    @staticmethod
    def _request_error(request):
        if request.status_code != 200:
            message = request.json().get('message')
            if not message:
                message = 'docker API returned HTTP code {}'.format(
                    request.status_code)
            print(message, file=sys.stderr)
            return True
        return False

    @classmethod
    def _handle_request(cls, request):
        import json

        if cls._request_error(request):
            return 1
        status_line = {}
        buf = b''
        for content in request.iter_content(chunk_size=None):
            if not content:
                continue
            # Sometimes, a chunk of content is not a complete json, so we
            # cumulate with leftovers from previous iterations.
            buf += content
            try:
                data = json.loads(buf)
            except Exception:
                continue
            buf = b''
            # data is sometimes an empty dict.
            if not data:
                continue
            # Mimick how docker itself presents the output. This code was
            # tested with API version 1.18 and 1.26.
            if 'status' in data:
                if 'id' in data:
                    if sys.stderr.isatty():
                        total_lines = len(status_line)
                        line = status_line.setdefault(data['id'], total_lines)
                        n = total_lines - line
                        if n > 0:
                            # Move the cursor up n lines.
                            sys.stderr.write('\033[{}A'.format(n))
                        # Clear line and move the cursor to the beginning of
                        # it.
                        sys.stderr.write('\033[2K\r')
                        sys.stderr.write('{}: {} {}\n'.format(
                            data['id'], data['status'],
                            data.get('progress', '')))
                        if n > 1:
                            # Move the cursor down n - 1 lines, which,
                            # considering the carriage return on the last
                            # write, gets us back where we started.
                            sys.stderr.write('\033[{}B'.format(n - 1))
                    else:
                        status = status_line.get(data['id'])
                        # Only print status changes.
                        if status != data['status']:
                            sys.stderr.write('{}: {}\n'.format(data['id'],
                                                               data['status']))
                            status_line[data['id']] = data['status']
                else:
                    status_line = {}
                    sys.stderr.write('{}\n'.format(data['status']))
            elif 'stream' in data:
                sys.stderr.write(data['stream'])
            elif 'error' in data:
                print(data['error'], file=sys.stderr)
                code = data.get('errorDetail', {}).get('code', None)
                return 1 if code is None else code
            else:
                raise NotImplementedError(repr(data))
            sys.stderr.flush()

    @classmethod
    def build(cls, image):
        session = docker_session()
        if isinstance(image.base, DockerImage):
            r = session.get(
                docker_url('images/{}/json'.format(image.base.tag)))
            if r.status_code == 404:
                ret = cls.load(image.base)
                if ret:
                    return ret
            elif cls._request_error(r):
                return 1
            # Consume the output, even if we don't use it.
            r.content

        context = BytesIO()
        image.send_context_to(context)
        r = session.post(
            docker_url('build', nocache=1, t=image.tag),
            data=context.getvalue(),
            stream=True,
            headers={'Content-Type': 'application/x-tar'},
        )
        return cls._handle_request(r)

    @classmethod
    def context(cls, image):
        if not cls._valid_stdout():
            return 1
        image.send_context_to(sys.stdout)

    @classmethod
    def load(cls, image):
        import requests
        import zstd

        taskId = Task.by_index[image.index]
        if not isinstance(taskId, Task.by_index.Existing):
            print(
                'Could not find a cached "{}" docker image'.format(image.name),
                file=sys.stderr)
            return 1

        r = requests.get(ARTIFACT_URL.format(taskId, 'public/image.tar.zst'),
                         stream=True)
        if r.status_code != 200:
            print()
            return 1

        r = docker_session().post(
            docker_url('images/load', quiet=0),
            data=zstd.ZstdDecompressor().read_from(r.raw),
            stream=True,
            headers={'Content-Type': 'application/x-tar'},
        )
        return cls._handle_request(r)

    @classmethod
    def save(cls, image):
        import zstd

        r = docker_session().get(
            docker_url('images/{}/get'.format(image.tag)),
            stream=True,
        )
        if cls._request_error(r):
            return 1
        if not cls._valid_stdout():
            return 1
        level = int(os.environ.get('DOCKER_IMAGE_ZSTD_LEVEL', '10'))
        compressor = zstd.ZstdCompressor(threads=-1, level=level,
                                         write_checksum=True).compressobj()
        for raw in r.iter_content(zstd.COMPRESSION_RECOMMENDED_INPUT_SIZE):
            chunk = compressor.compress(raw)
            if chunk:
                sys.stdout.buffer.write(chunk)

        chunk = compressor.flush()
        if chunk:
            sys.stdout.buffer.write(chunk)


if __name__ == '__main__':
    import argparse
    import logging
    logging.basicConfig(level=logging.DEBUG)

    commands = tuple(c for c in dir(CommandHandler) if not c.startswith('_'))
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=commands)
    parser.add_argument('name', choices=DOCKER_IMAGES.keys(),
                        help='Help of the docker image to build')
    args = parser.parse_args()
    image = DockerImage(args.name)
    sys.exit(getattr(CommandHandler, args.command)(image))
