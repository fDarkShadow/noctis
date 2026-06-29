#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("OFBIZ_MODE", "patched") == "vuln"

RCE_BODY = (
    b"<html><head><title>OFBiz Error</title></head><body>"
    b"<b>ERROR:</b> An unexpected error occurred in OFBiz.<br/>"
    b"java.lang.Exception: uid=0(root) gid=0(root) groups=0(root)"
    b"</body></html>"
)

LOGIN_REDIRECT = b"/webtools/control/main?USERNAME=&PASSWORD=&requirePasswordChange=Y"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location.decode() if isinstance(location, bytes) else location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if self.path in ("/", "/webtools/control/main"):
            self._send(200, b"<html><body><h1>Apache OFBiz</h1></body></html>")
        else:
            self._send(404, b"Not Found", ct="text/plain")

    def do_POST(self):
        if self.path == "/webtools/control/main/ProgramExport":
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            if VULN_MODE:
                self._send(200, RCE_BODY)
            else:
                self._redirect(LOGIN_REDIRECT)
        else:
            self._send(404, b"Not Found", ct="text/plain")


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
