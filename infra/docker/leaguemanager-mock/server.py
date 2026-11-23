#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("LEAGUEMANAGER_MODE", "patched") == "vuln"

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
        # LeagueManager unauthenticated CSV export endpoint.
        if p.startswith("/wp-admin/admin.php") and "page=leaguemanager-export" in p:
            if VULN_MODE:
                # Vulnerable: export is reachable unauthenticated and leaks the
                # league column headers.
                self._send(200,
                    "Season,Team,Website,Coach,Home,Points\r\n"
                    "2013,Rangers,http://example.org,J. Doe,Stadium,42\r\n",
                    ct="text/csv")
            else:
                # Patched: export requires auth → redirect to login (no headers).
                self._send(302, "", ct="text/html")
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
