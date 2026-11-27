#!/usr/bin/env python3
# Mock for CVE-2021-3129 — Laravel Ignition Debug Mode RCE.
#
# Vuln mode: POST /_ignition/execute-solution with the php://filter solution
# returns HTTP 500 reflecting decoded Laravel log output (command result +
# Illuminate framework stack), as a debug-mode Ignition install would.
# Patched mode: the endpoint is disabled (debug off / package patched) — 404.
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("LARAVEL_MODE", "patched") == "vuln"

# Decoded output a successful php://filter chain reflects from the Laravel log:
# the earlier `id` command result plus the Illuminate exception stack.
VULN_BODY = (
    "NOCTIS_LARAVEL_CONFIRMED\n"
    "uid=0(root) gid=0(root) groups=0(root)\n"
    '{"message":"The stream or file \\"../storage/logs/laravel.log\\" could not '
    "be opened in append mode\",\"exception\":"
    '"Illuminate\\\\Contracts\\\\Filesystem\\\\FileNotFoundException",'
    '"file":"/var/www/html/vendor/laravel/framework/src/Illuminate/'
    'Foundation/Bootstrap/HandleExceptions.php","line":255}'
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(404, "Not found", ct="text/plain")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        _ = self.rfile.read(length) if length else b""
        if self.path == "/_ignition/execute-solution":
            if VULN_MODE:
                self._send(500, VULN_BODY)
            else:
                # Patched / debug off — endpoint not exposed.
                self._send(404, "Not found", ct="text/plain")
        else:
            self._send(404, "Not found", ct="text/plain")


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
