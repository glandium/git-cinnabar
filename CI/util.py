import os


def build_commit(head='HEAD'):
    from cinnabar.git import Git
    from cinnabar.util import one
    return one(Git.iter(
        '-C', os.path.join(os.path.dirname(__file__), '..'),
        'rev-parse', '--verify', head, stderr=open(os.devnull, 'wb'))).decode()
