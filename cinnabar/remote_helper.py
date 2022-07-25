import sys

from cinnabar.hg.bundle import PushStore


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

    stdout = sys.stdout.buffer
    for node, parents in bundle_commits:
        if len(parents) > 2:
            raise Exception(
                'Pushing octopus merges to mercurial is not supported')

        changeset_data = store.read_changeset_data(node)
        if changeset_data is None:
            store.create_hg_metadata(node, parents)
        hg_changeset = store._changeset(node)
        stdout.write(b'%s %s %s\n' % (
            hg_changeset.node, hg_changeset.parent1, hg_changeset.parent2))

    stdout.flush()
