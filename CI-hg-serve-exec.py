import base64
import subprocess
from threading import Thread

from mercurial import cmdutil
from mercurial import hgweb
from mercurial.hgweb import common
try:
    httpservice = hgweb.httpservice
except AttributeError:
    from mercurial.commands import httpservice


cmdtable = {}
command = cmdutil.command(cmdtable)


def perform_authentication(hgweb, req, op):
    if req.env.get('REQUEST_METHOD') == 'POST':
        auth = req.env.get('HTTP_AUTHORIZATION')
        if not auth:
            raise common.ErrorResponse(
                common.HTTP_UNAUTHORIZED, 'who',
                [('WWW-Authenticate', 'Basic Realm="mercurial"')])
        user, password = base64.b64decode(auth.split()[1]).split(':', 1)
        req.env['REMOTE_USER'] = user


def extsetup():
    common.permhooks.insert(0, perform_authentication)


@command('serve-and-exec')
def serve_and_exec(ui, repo, *command):
    ui.setconfig('web', 'push_ssl', False, 'hgweb')
    ui.setconfig('web', 'allow_push', 'foo', 'hgweb')
    # For older versions of mercurial
    repo.baseui.setconfig('web', 'push_ssl', False, 'hgweb')
    repo.baseui.setconfig('web', 'allow_push', 'foo', 'hgweb')
    app = hgweb.hgweb(repo, baseui=ui)
    service = httpservice(ui, app, {'port': 8000})
    print command
    service.init()
    service_thread = Thread(target=service.run)
    service_thread.start()
    ret = subprocess.call(command)
    service.httpd.shutdown()
    service_thread.join()
    return ret
