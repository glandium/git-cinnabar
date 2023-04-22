# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import print_function
import base64
import os
import shutil
import subprocess
try:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    from SimpleHTTPServer import SimpleHTTPRequestHandler
except ImportError:
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from http.server import SimpleHTTPRequestHandler
from threading import Thread

try:
    from mercurial import cmdutil
    cmdutil.command
except AttributeError:
    from mercurial import registrar as cmdutil
from mercurial import hgweb
from mercurial.hgweb import common
from mercurial.hgweb.server import openlog
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


def HgLogging(cls):
    class Logging(cls):
        # Copied from mercurial's hgweb/server.py.
        def _log_any(self, fp, format, *args):
            message = '%s - - [%s] %s' % (self.client_address[0],
                                          self.log_date_time_string(),
                                          format % args) + '\n'
            if not isinstance(message, bytes):
                message = message.encode('utf-8')
            fp.write(message)
            fp.flush()

        def log_error(self, format, *args):
            self._log_any(self.server.errorlog, format, *args)

        def log_message(self, format, *args):
            self._log_any(self.server.accesslog, format, *args)

    return Logging


class GitServer(HgLogging(BaseHTTPRequestHandler)):
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
        if hasattr(self, 'flush_headers'):
            self.flush_headers()
        if self.command == 'POST':
            length = self.headers.get('Content-Length')
            env['CONTENT_LENGTH'] = length
            env['CONTENT_TYPE'] = self.headers.get('Content-Type')
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
    def __init__(self, typ, ui):
        if typ == b'git':
            cls = GitServer
        elif typ == b'http':
            cls = HgLogging(SimpleHTTPRequestHandler)
        else:
            assert False
        self.httpd = HTTPServer(
            ('', ui.configint(b'serve', b'otherport', 8080)),
            cls,
        )
        self.httpd.accesslog = openlog(
            ui.config(b'web', b'accesslog'), ui.fout)
        self.httpd.errorlog = openlog(ui.config(b'web', b'errorlog'), ui.ferr)

    def run(self):
        self.httpd.serve_forever()


@command(b'serve-and-exec', ())
def serve_and_exec(ui, repo, *command):
    other_server = ui.config(b'serve', b'other', None)
    if other_server:
        other_server = OtherServer(other_server, ui)
        other_server_thread = Thread(target=other_server.run)
        other_server_thread.start()
    ui.setconfig(b'web', b'push_ssl', False, b'hgweb')
    ui.setconfig(b'web', b'allow_push', b'*', b'hgweb')
    # For older versions of mercurial
    repo.baseui.setconfig(b'web', b'push_ssl', False, b'hgweb')
    repo.baseui.setconfig(b'web', b'allow_push', b'*', b'hgweb')
    app = hgweb.hgweb(repo, baseui=ui)
    service = httpservice(ui, app, {
        b'port': ui.configint(b'web', b'port', 8000),
        b'print_url': False
    })
    service.init()
    service_thread = Thread(target=service.run)
    service_thread.start()
    ret = subprocess.call(
        [getattr(os, "fsdecode", lambda a: a)(a) for a in command])
    service.httpd.shutdown()
    service_thread.join()
    if other_server:
        other_server.httpd.shutdown()
        other_server_thread.join()
    return ret
