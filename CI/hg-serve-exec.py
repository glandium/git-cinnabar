from __future__ import print_function
import base64
import os
import shutil
import subprocess
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
from threading import Thread

try:
    from mercurial import cmdutil
    cmdutil.command
except AttributeError:
    from mercurial import registrar as cmdutil
from mercurial import hgweb
from mercurial.hgweb import common
try:
    httpservice = hgweb.httpservice
except AttributeError:
    try:
        from mercurial import commands
        httpservice = commands.httpservice
    except AttributeError:
        from mercurial import util
        from mercurial.hgweb import server

        # Mercurial < 2.8 doesn't have this class. Copied from mercurial
        # revision e48c70451afcba7f2a27fae1c7d827638f1e372b
        class httpservice(object):
            def __init__(self, ui, app, opts):
                self.ui = ui
                self.app = app
                self.opts = opts

            def init(self):
                util.setsignalhandler()
                self.httpd = server.create_server(self.ui, self.app)

                if self.opts['port'] and not self.ui.verbose:
                    return

                if self.httpd.prefix:
                    prefix = self.httpd.prefix.strip('/') + '/'
                else:
                    prefix = ''

                port = ':%d' % self.httpd.port
                if port == ':80':
                    port = ''

                bindaddr = self.httpd.addr
                if bindaddr == '0.0.0.0':
                    bindaddr = '*'
                elif ':' in bindaddr:  # IPv6
                    bindaddr = '[%s]' % bindaddr

                fqaddr = self.httpd.fqaddr
                if ':' in fqaddr:
                    fqaddr = '[%s]' % fqaddr
                if self.opts['port']:
                    write = self.ui.status
                else:
                    write = self.ui.write
                write('listening at http://%s%s/%s (bound to %s:%d)\n' %
                      (fqaddr, port, prefix, bindaddr, self.httpd.port))

            def run(self):
                self.httpd.serve_forever()


cmdtable = {}
command = cmdutil.command(cmdtable)


def perform_authentication(hgweb, req, op):
    if hasattr(req, 'env'):
        env = req.env
    else:
        env = req.rawenv
    if env.get('REQUEST_METHOD') == 'POST':
        auth = env.get('HTTP_AUTHORIZATION')
        if not auth:
            raise common.ErrorResponse(
                common.HTTP_UNAUTHORIZED, 'who',
                [('WWW-Authenticate', 'Basic Realm="mercurial"')])
        if base64.b64decode(auth.split()[1]).split(':', 1) != ['foo', 'bar']:
            raise common.ErrorResponse(common.HTTP_FORBIDDEN, 'no')


def extsetup(ui):
    common.permhooks.insert(0, perform_authentication)


class GitServer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.git_http_backend()

    def do_POST(self):
        self.git_http_backend()

    def git_http_backend(self):
        env = dict(os.environ)
        env['REQUEST_METHOD'] = self.command
        env['GIT_HTTP_EXPORT_ALL'] = '1'
        env['GIT_PROJECT_ROOT'] = os.path.abspath(os.curdir)
        path, _, query = self.path.partition('?')
        env['PATH_INFO'] = path
        env['QUERY_STRING'] = query
        self.send_response(200, "Script output follows")
        if self.command == 'POST':
            length = self.headers.getheader('Content-Length')
            env['CONTENT_LENGTH'] = length
            env['CONTENT_TYPE'] = self.headers.getheader('Content-Type')
            try:
                length = int(length)
            except (TypeError, ValueError):
                length = 0
            data = self.rfile.read(length)
            stdin = subprocess.PIPE
        else:
            stdin = None

        p = subprocess.Popen(['git', 'http-backend'], stdin=stdin,
                             stdout=subprocess.PIPE, env=env)
        if stdin:
            p.stdin.write(data)
            p.stdin.close()
        shutil.copyfileobj(p.stdout, self.wfile)
        p.stdout.close()


class OtherServer(object):
    def __init__(self, typ):
        if typ == 'git':
            cls = GitServer
        elif typ == 'http':
            cls = SimpleHTTPRequestHandler
        else:
            assert False
        self.httpd = HTTPServer(('', 8080), cls)

    def run(self):
        self.httpd.serve_forever()


@command('serve-and-exec', ())
def serve_and_exec(ui, repo, *command):
    other_server = os.environ.get('OTHER_SERVER')
    if other_server:
        other_server = OtherServer(other_server)
        other_server_thread = Thread(target=other_server.run)
        other_server_thread.start()
    ui.setconfig('web', 'push_ssl', False, 'hgweb')
    ui.setconfig('web', 'allow_push', '*', 'hgweb')
    # For older versions of mercurial
    repo.baseui.setconfig('web', 'push_ssl', False, 'hgweb')
    repo.baseui.setconfig('web', 'allow_push', '*', 'hgweb')
    app = hgweb.hgweb(repo, baseui=ui)
    service = httpservice(ui, app, {'port': 8000, 'print_url': False})
    print(command)
    service.init()
    service_thread = Thread(target=service.run)
    service_thread.start()
    ret = subprocess.call(command)
    service.httpd.shutdown()
    service_thread.join()
    if other_server:
        other_server.httpd.shutdown()
        other_server_thread.join()
    return ret
