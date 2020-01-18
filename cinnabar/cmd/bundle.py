from __future__ import absolute_import, unicode_literals
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
from cinnabar.util import fsencode


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

    revs = [fsencode(r) for r in args.rev]
    bundle_commits = list((c, p) for c, t, p in GitHgHelper.rev_list(
        b'--topo-order', b'--full-history', b'--parents', b'--reverse', *revs))
    if bundle_commits:
        # TODO: better UX. For instance, this will fail with an exception when
        # the parent commit doesn't have mercurial metadata.
        GRAFT = {
            None: False,
            b'false': False,
            b'true': True,
        }
        try:
            graft = Git.config('cinnabar.graft', values=GRAFT)
        except InvalidConfig as e:
            logging.error(str(e))
            return 1
        store = PushStore(graft=graft)
        if args.version == 1:
            b2caps = {}
        elif args.version == 2:
            b2caps = {
                b'HG20': (),
                b'changegroup': (b'01', b'02'),
            }
        with open(args.path, 'wb') as fh:
            if not b2caps:
                fh.write(b'HG10UN')
            for data in create_bundle(store, bundle_commits, b2caps):
                fh.write(data)
        store.close(rollback=True)


@CLI.subcommand
@CLI.argument('--clonebundle', action='store_true',
              help='get clone bundle from given repository')
@CLI.argument('url', help='url of the bundle')
def unbundle(args):
    '''apply a mercurial bundle to the repository'''
    # Make git emit its error when the current directory is not in a git repo.
    proc = GitProcess('rev-parse')
    ret = proc.wait()
    if ret:
        return ret
    remote = Remote(b'', fsencode(args.url))
    if remote.parsed_url.scheme not in (b'file', b'http', b'https'):
        logging.error('%s urls are not supported.' % remote.parsed_url.scheme)
        return 1
    if args.clonebundle:
        repo = get_repo(remote)
        if not repo.capable(b'clonebundles'):
            logging.error('Repository does not support clonebundles')
            return 1
        bundle = get_clonebundle(repo)
    else:
        bundle = get_bundle(remote.url)

    store = GitHgStore()
    GRAFT = {
        None: False,
        b'false': False,
        b'true': True,
    }
    try:
        graft = Git.config('cinnabar.graft', values=GRAFT)
    except InvalidConfig as e:
        logging.error(str(e))
        return 1
    if graft:
        store.prepare_graft()
    bundle = unbundler(bundle)
    apply_bundle = BundleApplier(bundle)
    del bundle
    apply_bundle(store)
    store.close()
