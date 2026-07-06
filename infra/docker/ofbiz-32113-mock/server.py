#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("OFBIZ_32113_MODE", "patched") == "vuln"

RCE_BODY = (
    "java.lang.Exception: uid=0(root) gid=0(root) groups=0(root)\n"
    "\tat sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)\n"
    "\tat org.apache.ofbiz.base.util.GroovyUtil.evaluate(GroovyUtil.java:234)\n"
).encode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain", location=None):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def do_POST(self):
        raw_body = self._read_body()
        path_lower = self.path.lower()

        if "programexport" not in path_lower:
            self._send(404, b"Not found")
            return

        if not VULN_MODE:
            self._send(302, b"", location="/webtools/control/main")
            return

        if b"groovyprogram" in raw_body.lower():
            self._send(200, RCE_BODY)
        else:
            self._send(302, b"", location="/webtools/control/main")

    def do_GET(self):
        self._send(200, b"<html><body>Apache OFBiz</body></html>", "text/html")


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
