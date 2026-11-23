#!/usr/bin/env python3
"""Mock NetGear ReadyNAS RAIDiator FrontView — CVE-2013-2751 / CVE-2013-2752.

Vuln mode:
  * GET /np_handler/ returns the FrontView handler marker "Empty No Support".
  * GET /np_handler/np_handler.pl?...addr=...`id`... (the command-injection
    payload) reflects the executed command output (uid=.../gid=...).
Patched mode: the np_handler endpoints are absent (404) → zero findings.

Requests arrive verbatim over tcp_connect, so self.path keeps the %xx encoding
of the injection payload; the vuln branch matches on the raw path.
"""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("NETGEAR_READYNAS_MODE", "patched") == "vuln"

CMD_OUTPUT = "uid=0(root) gid=0(root) groups=0(root)\n"


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache"
    sys_version = ""

    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path  # raw, %xx preserved
        if VULN_MODE and path.startswith("/np_handler/np_handler.pl"):
            # Command-injection payload: backtick-wrapped `id` (%60id%60).
            if "%60id%60" in path or "`id`" in path:
                self._send(200, "np_handler result:\n" + CMD_OUTPUT)
            else:
                self._send(200, "np_handler.pl")
            return
        if VULN_MODE and path == "/np_handler/":
            self._send(200, "np_handler: Empty No Support")
            return
        self._send(404, "Not Found")

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
