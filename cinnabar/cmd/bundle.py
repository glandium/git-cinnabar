from cinnabar.cmd.util import CLI
from cinnabar.helper import GitHgHelper
from cinnabar.hg.bundle import (
    create_bundle,
    PushStore,
)
from cinnabar.hg import unbundle20


@CLI.subcommand
@CLI.argument('--version', choices=(1, 2), type=int,
              default=2 if unbundle20 else 1,
              help='bundle version')
@CLI.argument('path', help='path of the bundle')
@CLI.argument('rev', nargs='+',
              help='git revision range (see the Specifying Ranges'
                   ' section of gitrevisions(7))')
def bundle(args):
    '''create a mercurial bundle'''

    bundle_commits = list((c, p) for c, t, p in GitHgHelper.rev_list(
        '--topo-order', '--full-history', '--parents', '--reverse', *args.rev))
    if bundle_commits:
        # TODO: enable graft support
        # TODO: better UX. For instance, this will fail with an exception when
        # the parent commit doesn't have mercurial metadata.
        store = PushStore()
        store.init_fast_import()
        if args.version == 1:
            b2caps = {}
        elif args.version == 2:
            b2caps = {
                'HG20': (),
                'changegroup': ('01', '02'),
            }
        with open(args.path, 'wb') as fh:
            if not b2caps:
                fh.write('HG10UN')
            for data in create_bundle(store, bundle_commits, b2caps):
                fh.write(data)
        store.close(rollback=True)
