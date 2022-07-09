import os
from cinnabar.cmd.util import CLI
from cinnabar.helper import GitHgHelper
from cinnabar.hg.bundle import (
    create_bundle,
    PushStore,
)


@CLI.subcommand
@CLI.argument('--version', choices=(1, 2), type=int,
              default=2,
              help='bundle version')
@CLI.argument('path', help='path of the bundle')
@CLI.argument('rev', nargs='+',
              help='git revision range (see the Specifying Ranges'
                   ' section of gitrevisions(7))')
def bundle(args):
    '''create a mercurial bundle'''

    revs = [os.fsencode(r) for r in args.rev]
    bundle_commits = list((c, p) for c, t, p in GitHgHelper.rev_list(
        b'--topo-order', b'--full-history', b'--parents', b'--reverse', *revs))
    if bundle_commits:
        # TODO: better UX. For instance, this will fail with an exception when
        # the parent commit doesn't have mercurial metadata.
        store = PushStore()
        kwargs = {
            'path': args.path,
        }
        if args.version == 1:
            kwargs['bundlespec'] = b'none-v1'
            kwargs['cg_version'] = b'01'
        elif args.version == 2:
            kwargs['bundlespec'] = b'none-v2'
            kwargs['cg_version'] = b'02'
        create_bundle(store, bundle_commits, **kwargs)
        store.close(rollback=True)
