from __future__ import absolute_import
import logging
from cinnabar.cmd.util import CLI
from cinnabar.git import (
    Git,
    GitProcess,
    InvalidConfig,
)
from cinnabar.githg import GitHgStore
from cinnabar.helper import GitHgHelper
from cinnabar.hg.bundle import (
    create_bundle,
    PushStore,
)
from cinnabar.hg.repo import (
    BundleApplier,
    get_bundle,
    get_clonebundle,
    get_repo,
    Remote,
    unbundle20,
    unbundler,
)


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
        # TODO: better UX. For instance, this will fail with an exception when
        # the parent commit doesn't have mercurial metadata.
        GRAFT = {
            None: False,
            'false': False,
            'true': True,
        }
        try:
            graft = Git.config('cinnabar.graft', values=GRAFT)
        except InvalidConfig as e:
            logging.error(e.message)
            return 1
        store = PushStore(graft=graft)
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


@CLI.subcommand
@CLI.argument('--clonebundle', action='store_true',
              help='get clone bundle from given repository')
@CLI.argument('url', help='url of the bundle')
def unbundle(args):
    # Make git emit its error when the current directory is not in a git repo.
    proc = GitProcess('rev-parse')
    ret = proc.wait()
    if ret:
        return ret
    remote = Remote('', args.url)
    if remote.parsed_url.scheme not in ('file', 'http', 'https'):
        logging.error('%s urls are not supported.' % remote.parsed_url.scheme)
        return 1
    if args.clonebundle:
        repo = get_repo(remote)
        if not repo.capable('clonebundles'):
            logging.error('Repository does not support clonebundles')
            return 1
        bundle = get_clonebundle(repo)
    else:
        bundle = get_bundle(remote.url)

    store = GitHgStore()
    GRAFT = {
        None: False,
        'false': False,
        'true': True,
    }
    try:
        graft = Git.config('cinnabar.graft', values=GRAFT)
    except InvalidConfig as e:
        logging.error(e.message)
        return 1
    if graft:
        store.prepare_graft()
    bundle = unbundler(bundle)
    apply_bundle = BundleApplier(bundle)
    del bundle
    apply_bundle(store)
    store.close()
