#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("CIVICRM_MODE", "patched") == "vuln"

# Marker reflected by the injected UNION SELECT, per the OpenVAS plugin.
MARKER = "sql-injection-test"

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
        p = self.path
        # CiviCRM jqState AJAX endpoint — the injectable parameter.
        if "page=CiviCRM" in p and "civicrm/ajax/jqState" in p:
            if VULN_MODE:
                # Vulnerable: the UNION SELECT reflects the marker into output.
                self._send(200,
                    '{"name":"%s"}' % MARKER, ct="application/json")
            else:
                # Patched (or benign request): empty/benign AJAX response.
                self._send(200, '{"name":""}', ct="application/json")
        else:
            self._send(404, "<html><body>404 Not Found</body></html>")

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
