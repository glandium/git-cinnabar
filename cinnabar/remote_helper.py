import sys

from cinnabar.hg.bundle import (
    PushStore,
    create_bundle,
)


def main():
    store = PushStore()

    bundle_commits = []
    while True:
        line = sys.stdin.buffer.readline().strip()
        if not line:
            break
        commit, _, parents = line.partition(b' ')
        bundle_commits.append(
            (commit, parents.split(b' ') if parents else []))

    create_bundle(store, bundle_commits)
