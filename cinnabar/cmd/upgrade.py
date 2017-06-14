from cinnabar.cmd.util import CLI
from cinnabar.githg import (
    GitHgStore,
    UpgradeException,
)
from cinnabar.helper import GitHgHelper


class UpgradeGitHgStore(GitHgStore):
    def metadata(self):
        return self._metadata()


@CLI.subcommand
def upgrade(args):
    '''upgrade cinnabar metadata'''

    try:
        store = GitHgStore()
        print 'No metadata to upgrade'
        return 2
    except UpgradeException:
        store = UpgradeGitHgStore()

    if not GitHgHelper.upgrade():
        print 'Cannot finish upgrading... You may need to reclone.'
        return 1

    print 'Finalizing upgrade...'
    store.close()
    print (
        'You may want to run `git cinnabar fsck --files` to ensure '
        'the upgrade went well.\n'
        'Please be aware this might take a while.'
    )
    return 0
