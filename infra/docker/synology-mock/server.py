#!/usr/bin/env python3
# Mock for Synology BeeStation (BSM) — Synology-SA-24:21 active check
# (CVE-2024-50630 / CVE-2024-50631).
#
# Both modes serve the Synology webapi realistically: POST /webapi/entry.cgi
# answers with the normal JSON API reply/error, GET / returns a BSM landing
# fingerprint. The vulnerability is a CRLF / X-Accel-Redirect injection in the
# SYNO.API.Auth.RedirectURI handler's redirect_url parameter.
#
# Vuln mode: ONLY when the request body carries the injected X-Accel-Redirect
#   header (the real exploit payload) does nginx serve the internal Drive
#   worker log (cloud-workerd.log), whose embedded source-file names match the
#   OpenVAS pattern  (?m)^[0-9A-Z:-]+ \([0-9]+:[0-9]+\) \[INFO\].+\.(o|cpp)
# Patched mode: the handler strips the CRLF / rejects the injection and always
#   returns the normal JSON API error (no file served) → zero findings.
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("SYNOLOGY_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

# Served internal Drive worker log (/volume1/@synologydrive/log/cloud-workerd.log).
# A real log file starts with many lines before the source-file-bearing [INFO]
# entries — hence the line-anchored (?m) match in the feed.
LEAK = (
    "cloud-workerd 1.7.0-20242 starting\n"
    "config: /var/packages/SynologyDrive/etc/cloud-workerd.conf\n"
    "2024-10-21T03:14:08-05:00 (2041:2041) [INFO] job-queue-client.cpp.o:218 worker queue initialised\n"
    "2024-10-21T03:14:08-05:00 (2041:2041) [INFO] session finder authenticated\n"
    "2024-10-21T03:14:09-05:00 (2041:2047) [INFO] checkpoint-task.cpp.o:530 checkpoint flush ok\n"
)

# Normal Synology webapi error reply (what a patched box returns for the probe).
API_ERROR = '{"error":{"code":101},"success":false}'

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
            try:
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length) if length else b""
            except Exception:
                raw = b""
            body = raw.decode("latin-1", "replace")
            injected = ("redirect_url=" in body) and ("X-Accel-Redirect" in body)
            # Vulnerable box: the reflected redirect_url carries the CRLF-injected
            # X-Accel-Redirect, so nginx serves the internal log file instead of
            # the JSON reply. No injection → normal API reply (so the TP proves
            # the payload matters, not that the endpoint merely exists).
            if VULN_MODE and injected:
                self._send(200, LEAK)
            else:
                self._send(200, API_ERROR, ct="application/json")
        else:
            self._send(404, "Not found")

    def do_GET(self):
        # Realistic BSM/DSM login fingerprint on both vuln and patched instances.
        if self.path.split("?")[0] in ("/", "/webman/index.cgi"):
            self._send(200,
                       "<html><head><title>Synology BeeStation</title></head>"
                       "<body>Synology Drive</body></html>", ct="text/html")
        else:
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
