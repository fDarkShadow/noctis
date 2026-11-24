#!/usr/bin/env python3
# Mock for Bacula-Web 'jobid' SQL injection — CVE-2014-8295.
# Vuln mode: /joblogs.php reflects the raw 'jobid' value into a MySQL syntax
# error, mimicking the unsanitised query. Patched mode: parameterised query →
# a benign page with no SQL error, so zero findings.
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qsl

VULN_MODE = os.environ.get("BACULA_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
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
        parts = urlsplit(self.path)
        if parts.path == "/joblogs.php":
            # parse_qsl collapses %-encoding; keep the raw jobid so the
            # injected single quote and marker are reflected verbatim.
            jobid = ""
            for k, v in parse_qsl(parts.query, keep_blank_values=True):
                if k == "jobid":
                    jobid = v
            if VULN_MODE:
                body = (
                    "<html><body>"
                    "You have an error in your SQL syntax; check the manual that "
                    "corresponds to your MySQL server version for the right syntax "
                    "to use near '" + jobid + "' at line 1"
                    "</body></html>"
                )
                self._send(200, body)
            else:
                # Patched: jobid is cast/validated → no backend error leaked.
                self._send(200, "<html><body>No job logs found.</body></html>")
        else:
            self._send(404, "Not found")

    def do_POST(self):
        self.do_GET()


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(CERT_DIR, "server.crt"),
                        os.path.join(CERT_DIR, "server.key"))
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    if PORT_HTTPS:
        threading.Thread(
            target=lambda: _make_https_server(PORT_HTTPS).serve_forever(),
            daemon=True,
        ).start()
    if PORT_HTTP:
        HTTPServer(("0.0.0.0", PORT_HTTP), Handler).serve_forever()
    else:
        threading.Event().wait()
