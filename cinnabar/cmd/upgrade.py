from __future__ import absolute_import, print_function
from cinnabar.cmd.util import CLI
from cinnabar.exceptions import (
    OldUpgradeAbort,
    UpgradeAbort,
)
from cinnabar.githg import GitHgStore
from cinnabar.helper import GitHgHelper


class UpgradeGitHgStore(GitHgStore):
    def metadata(self):
        return self._metadata()


@CLI.subcommand
def upgrade(args):
    '''upgrade cinnabar metadata'''

    try:
        store = GitHgStore()
        print('No metadata to upgrade')
        return 2
    except OldUpgradeAbort:
        raise
    except UpgradeAbort:
        store = UpgradeGitHgStore()

    if not GitHgHelper.upgrade():
        print('Cannot finish upgrading... You may need to reclone.')
        return 1

    print('Finalizing upgrade...')
    store.close(refresh=store.METADATA_REFS)
    print(
        'You may want to run `git cinnabar fsck` to ensure the upgrade '
        'went well.\n'
    )
    return 0
