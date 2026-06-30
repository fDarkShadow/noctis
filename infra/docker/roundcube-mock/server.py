#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("ROUNDCUBE_MODE", "patched") == "vuln"
VERSION = "1.6.2" if VULN_MODE else "1.6.3"

LOGIN_HTML = """<html><head><title>Roundcube Webmail :: Welcome to Roundcube Webmail</title>
<script>var rcversion='{v}', rcube_server_version='{v}';</script>
</head><body>Login to Roundcube...</body></html>""".format(v=VERSION)

APP_JS = "/* Roundcube Webmail v{v} */\nvar rcmail = null;\n".format(v=VERSION)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/?_task=login") or self.path == "/":
            self._send(200, LOGIN_HTML)
        elif self.path == "/program/js/app.js":
            self._send(200, APP_JS, "application/javascript")
        else:
            self._send(404, "Not found", "text/plain")

    def do_POST(self):
        self.do_GET()


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/certs/server.crt", "/certs/server.key")
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    https = _make_https_server(443)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
