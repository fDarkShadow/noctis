#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("LEAGUEMANAGER_MODE", "patched") == "vuln"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html", headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            n = 0
        return self.rfile.read(n).decode("latin-1") if n else ""

    def do_POST(self):
        # LeagueManager export handler. The plugin only runs the export when the
        # `leaguemanager_export` POST field is present; the SQLi lives in
        # `league_id`. Require the genuine NASL payload (not self-fulfilling:
        # the CSV column headers are server-produced, never echoed from input).
        if self.path.startswith("/wp-admin/admin.php") and "page=leaguemanager-export" in self.path:
            body = self._read_body()
            injected = ("leaguemanager_export=Download+File" in body
                        and "union select" in body.lower()
                        and "wp_users" in body.lower())
            if injected and VULN_MODE:
                # Vulnerable: export runs unauthenticated and the UNION leaks
                # the user table into the exported CSV column headers.
                self._send(200,
                    "Season,Team,Website,Coach,Home,Points\r\n"
                    "2013,Rangers,http://example.org,admin,wp_hashed_pass,42\r\n",
                    ct="text/csv")
            else:
                # Patched (or missing export field): unauthenticated users are
                # redirected to the WordPress login — no CSV, no headers.
                self._send(302, "", headers={"Location": "/wp-login.php"})
        else:
            self._send(404, "<html><body>404 Not Found</body></html>")

    def do_GET(self):
        # A bare GET on a real WordPress just bounces to the login page.
        if self.path.startswith("/wp-admin/admin.php") and "page=leaguemanager-export" in self.path:
            self._send(302, "", headers={"Location": "/wp-login.php"})
        else:
            self._send(404, "<html><body>404 Not Found</body></html>")


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
