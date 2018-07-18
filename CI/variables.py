import os


if 'TC_PROXY' in os.environ:
    PROXY_INDEX_URL = 'http://taskcluster/index/v1/task/{}'
else:
    PROXY_INDEX_URL = 'https://index.taskcluster.net/v1/task/{}'
ARTIFACT_URL = 'https://queue.taskcluster.net/v1/task/{}/artifacts/{}'

TC_LOGIN = os.environ.get('TC_LOGIN', 'glandium')
TC_REPO_NAME = os.environ.get('TC_REPO_NAME', 'git-cinnabar')
TC_REPO_URL = os.environ.get(
    'TC_REPO_URL',
    'https://github.com/{}/{}'.format(TC_LOGIN, TC_REPO_NAME))
TC_COMMIT = os.environ.get('TC_COMMIT', 'HEAD')
TC_BRANCH = os.environ.get('TC_BRANCH')
TC_IS_PUSH = os.environ.get('TC_IS_PUSH') == '1'
