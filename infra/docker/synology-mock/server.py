#!/usr/bin/env python3
# Mock for Synology BeeStation (BSM) — Synology-SA-24:21 active check
# (CVE-2024-50630 / CVE-2024-50631).
#
# Vuln mode: POST /webapi/entry.cgi leaks a Synology Drive Server debug/log
# line embedding the compiled source-file name, matching the OpenVAS pattern
#   ^[0-9A-Z:-]+ \([0-9]+:[0-9]+\) \[INFO\].+\.(o|cpp)
# Patched mode: the endpoint returns a benign JSON API error (no leaked line)
# → zero findings.
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("SYNOLOGY_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

# Leaked internal Drive Server debug line (source-file disclosure).
LEAK = ("2024-10-21 (1234:5678) [INFO] cloud_station/synced_folder/"
        "share_crypto_worker.cpp:482 crypto share enumeration\n")

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path.split("?")[0] == "/webapi/entry.cgi":
            # Drain request body (entry.cgi form params)
            try:
                length = int(self.headers.get("Content-Length", 0))
                if length: self.rfile.read(length)
            except Exception:
                pass
            if VULN_MODE:
                self._send(200, LEAK)
            else:
                self._send(200, '{"error":{"code":101},"success":false}',
                           ct="application/json")
        else:
            self._send(404, "Not found")

    def do_GET(self):
        self._send(404, "Not found")

def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(CERT_DIR, "server.crt"),
                        os.path.join(CERT_DIR, "server.key"))
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv

if __name__ == "__main__":
    if PORT_HTTPS:
        threading.Thread(target=lambda: _make_https_server(PORT_HTTPS).serve_forever(),
                         daemon=True).start()
    if PORT_HTTP:
        HTTPServer(("0.0.0.0", PORT_HTTP), Handler).serve_forever()
    else:
        threading.Event().wait()
