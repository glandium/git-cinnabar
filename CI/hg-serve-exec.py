# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import print_function

import base64
import os
import shutil
import subprocess
import sys

try:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    from SimpleHTTPServer import SimpleHTTPRequestHandler
except ImportError:
    from http.server import BaseHTTPRequestHandler, HTTPServer, SimpleHTTPRequestHandler
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

                if self.opts["port"] and not self.ui.verbose:
                    return

                if self.httpd.prefix:
                    prefix = self.httpd.prefix.strip("/") + "/"
                else:
                    prefix = ""

                port = ":%d" % self.httpd.port
                if port == ":80":
                    port = ""

                bindaddr = self.httpd.addr
                if bindaddr == "0.0.0.0":
                    bindaddr = "*"
                elif ":" in bindaddr:  # IPv6
                    bindaddr = "[%s]" % bindaddr

                fqaddr = self.httpd.fqaddr
                if ":" in fqaddr:
                    fqaddr = "[%s]" % fqaddr
                if self.opts["port"]:
                    write = self.ui.status
                else:
                    write = self.ui.write
                write(
                    "listening at http://%s%s/%s (bound to %s:%d)\n"
                    % (fqaddr, port, prefix, bindaddr, self.httpd.port)
                )

            def run(self):
                self.httpd.serve_forever()


cmdtable = {}
command = cmdutil.command(cmdtable)


def perform_authentication(hgweb, req, op):
    if hasattr(req, "env"):
        env = req.env
    else:
        env = req.rawenv
    if (
        env.get(b"REQUEST_METHOD") == b"POST"
        and env.get(b"QUERY_STRING") == b"cmd=unbundle"
    ):
        auth = env.get(b"HTTP_AUTHORIZATION")
        if not auth:
            raise common.ErrorResponse(
                common.HTTP_UNAUTHORIZED,
                b"who",
                [(b"WWW-Authenticate", b'Basic Realm="mercurial"')],
            )
        if base64.b64decode(auth.split()[1]).split(b":", 1) != [b"foo", b"bar"]:
            raise common.ErrorResponse(common.HTTP_FORBIDDEN, b"no")


def extsetup(ui):
    common.permhooks.insert(0, perform_authentication)


def HgLogging(cls):
    class Logging(cls):
        # Copied from mercurial's hgweb/server.py.
        def _log_any(self, fp, format, *args):
            message = (
                "%s - - [%s] %s"
                % (self.client_address[0], self.log_date_time_string(), format % args)
                + "\n"
            )
            if not isinstance(message, bytes):
                message = message.encode("utf-8")
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
        env["REQUEST_METHOD"] = self.command
        env["GIT_HTTP_EXPORT_ALL"] = "1"
        env["GIT_PROJECT_ROOT"] = os.path.abspath(os.curdir)
        path, _, query = self.path.partition("?")
        env["PATH_INFO"] = path
        env["QUERY_STRING"] = query
        self.send_response(200, "Script output follows")
        if hasattr(self, "flush_headers"):
            self.flush_headers()
        if self.command == "POST":
            length = self.headers.get("Content-Length")
            env["CONTENT_LENGTH"] = length
            env["CONTENT_TYPE"] = self.headers.get("Content-Type")
            try:
                length = int(length)
            except (TypeError, ValueError):
                length = 0
            data = self.rfile.read(length)
            stdin = subprocess.PIPE
        else:
            stdin = None

        p = subprocess.Popen(
            ["git", "http-backend"], stdin=stdin, stdout=subprocess.PIPE, env=env
        )
        if stdin:
            p.stdin.write(data)
            p.stdin.close()
        shutil.copyfileobj(p.stdout, self.wfile)
        p.stdout.close()


class OtherServer(object):
    def __init__(self, typ, ui):
        if typ == b"git":
            cls = GitServer
        elif typ == b"http":
            cls = HgLogging(SimpleHTTPRequestHandler)
        else:
            assert False
        self.httpd = MyHTTPServer(
            ("localhost", ui.configint(b"serve", b"otherport", 8080)),
            cls,
        )
        self.httpd.accesslog = openlog(ui.config(b"web", b"accesslog"), ui.fout)
        self.httpd.errorlog = openlog(ui.config(b"web", b"errorlog"), ui.ferr)

    def run(self):
        self.httpd.serve_forever()


from mercurial.hgweb.server import MercurialHTTPServer

def create_srv(ui, app):
    from mercurial.hgweb.server import _httprequesthandlerssl, _httprequesthandler, IPv6HTTPServer
    from mercurial.utils import urlutil
    import socket
    from mercurial import error, encoding
    from mercurial.i18n import _
    if ui.config(b'web', b'certificate'):
        handler = _httprequesthandlerssl
    else:
        handler = _httprequesthandler

    if ui.configbool(b'web', b'ipv6'):
        cls = IPv6HTTPServer
    else:
        cls = MyMercurialHTTPServer

    sys.stderr.write("before mimetypes\n")
    # ugly hack due to python issue5853 (for threaded use)
    import mimetypes

    mimetypes.init()
    sys.stderr.write("after mimetypes\n")

    address = ui.config(b'web', b'address')
    port = urlutil.getport(ui.config(b'web', b'port'))
    sys.stderr.write("before %s ; %r\n" % (cls.__name__, (address, port)))
    try:
        return cls(ui, app, (address, port), handler)
    except socket.error as inst:
        raise error.Abort(
            _(b"cannot start server at '%s:%d': %s")
            % (address, port, encoding.strtolocal(inst.args[1]))
        )
    finally:
        sys.stderr.write("after %s ; %r\n" % (cls.__name__, (address, port)))


class MyHTTPServer(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        sys.stderr.write("enter MyHTTPServer.__init__\n")
        try:
            HTTPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        finally:
            sys.stderr.write("exit MyHTTPServer.__init__\n")

    def server_bind(self):
        import socketserver, socket
        sys.stderr.write("enter MyHTTPServer.server_bind\n")
        try:
            sys.stderr.write("before TCPServer.server_bind\n")
            socketserver.TCPServer.server_bind(self)
            sys.stderr.write("after TCPServer.server_bind\n")
            host, port = self.server_address[:2]
            self.server_name = socket.getfqdn(host)
            sys.stderr.write("after getfqdn %r\n" % host)
            self.server_port = port
        finally:
            sys.stderr.write("exit MyHTTPServer.server_bind\n")

    def server_activate(self):
        sys.stderr.write("enter MyHTTPServer.server_activate\n")
        try:
            HTTPServer.server_activate(self)
        finally:
            sys.stderr.write("exit MyHTTPServer.server_activate\n")

    def server_close(self):
        sys.stderr.write("enter MyHTTPServer.server_close\n")
        try:
            HTTPServer.server_close(self)
        finally:
            sys.stderr.write("exit MyHTTPServer.server_close\n")


class MyMercurialHTTPServer(MercurialHTTPServer, MyHTTPServer):
    def __init__(self, ui, app, addr, handler, **kwargs):
        MyHTTPServer.__init__(self, addr, handler, **kwargs)
        self.daemon_threads = True
        self.application = app

        handler.preparehttpserver(self, ui)

        prefix = ui.config(b'web', b'prefix')
        if prefix:
            prefix = b'/' + prefix.strip(b'/')
        self.prefix = prefix

        alog = openlog(ui.config(b'web', b'accesslog'), ui.fout)
        elog = openlog(ui.config(b'web', b'errorlog'), ui.ferr)
        self.accesslog = alog
        self.errorlog = elog

        self.addr, self.port = self.socket.getsockname()[0:2]
        self.fqaddr = self.server_name

        self.serverheader = ui.config(b'web', b'server-header')


@command(b"serve-and-exec", ())
def serve_and_exec(ui, repo, *command):
  from mercurial.hgweb import server
  create_server_ = server.create_server

  def create_server2(ui, app):
      sys.stderr.write("enter create_server\n")
      try:
        return create_srv(ui, app)
      finally:
        sys.stderr.write("exit create_server\n")

  server.create_server = create_server2

  sys.stderr.write("Started serve_and_exec\n")
  try:
    other_server = ui.config(b"serve", b"other", None)
    if other_server:
        other_server = OtherServer(other_server, ui)
        other_server_thread = Thread(target=other_server.run)
        other_server_thread.start()
    sys.stderr.write("serve_and_exec: after other server\n")
    ui.setconfig(b"web", b"push_ssl", False, b"hgweb")
    ui.setconfig(b"web", b"allow_push", b"*", b"hgweb")
    # For older versions of mercurial
    repo.baseui.setconfig(b"web", b"push_ssl", False, b"hgweb")
    repo.baseui.setconfig(b"web", b"allow_push", b"*", b"hgweb")
    sys.stderr.write("serve_and_exec: before hgweb\n")
    app = hgweb.hgweb(repo, baseui=ui)
    sys.stderr.write("serve_and_exec: after hgweb\n")
    service = httpservice(
        ui, app, {b"port": ui.configint(b"web", b"port", 8000), b"print_url": False}
    )
    sys.stderr.write("serve_and_exec: after httpservice\n")
    service.init()
    sys.stderr.write("serve_and_exec: after service.init\n")
    service_thread = Thread(target=service.run)
    service_thread.start()
    sys.stderr.write("serve_and_exec: after service_thread.start\n")
    ret = subprocess.call([getattr(os, "fsdecode", lambda a: a)(a) for a in command])
    sys.stderr.write("serve_and_exec: after subprocess\n")
    service.httpd.shutdown()
    service_thread.join()
    if other_server:
        other_server.httpd.shutdown()
        other_server_thread.join()
    return ret
  finally:
    sys.stderr.write("Ended serve_and_exec\n")
