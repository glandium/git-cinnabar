import os


if 'TASKCLUSTER_PROXY' in os.environ:
    PROXY_INDEX_URL = 'http://taskcluster/index/v1/task/{}'
else:
    PROXY_INDEX_URL = 'https://index.taskcluster.net/v1/task/{}'
ARTIFACT_URL = 'https://queue.taskcluster.net/v1/task/{}/artifacts/{}'

GITHUB_HEAD_USER = os.environ.get('GITHUB_HEAD_USER', 'glandium')
GITHUB_HEAD_USER_EMAIL = os.environ.get('GITHUB_HEAD_USER_EMAIL', 'glandium@')
GITHUB_HEAD_REPO_NAME = os.environ.get('GITHUB_HEAD_REPO_NAME', 'git-cinnabar')
GITHUB_HEAD_REPO_URL = os.environ.get(
    'GITHUB_HEAD_REPO_URL',
    'https://github.com/{}/{}'.format(GITHUB_HEAD_USER, GITHUB_HEAD_REPO_NAME))
GITHUB_HEAD_SHA = os.environ.get('GITHUB_HEAD_SHA', 'HEAD')
GITHUB_HEAD_BRANCH = os.environ.get('GITHUB_HEAD_BRANCH', 'HEAD')
GITHUB_BASE_USER = os.environ.get('GITHUB_BASE_USER', GITHUB_HEAD_USER)
GITHUB_BASE_REPO_NAME = os.environ.get('GITHUB_BASE_REPO_NAME',
                                       GITHUB_HEAD_REPO_NAME)
