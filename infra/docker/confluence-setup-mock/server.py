#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

VULN_MODE = os.environ.get("CONFLUENCE_MODE", "patched") == "vuln"

_lock = threading.Lock()
_setup_complete = True


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

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            return self.rfile.read(length).decode("utf-8", errors="replace")
        return ""

    def do_GET(self):
        global _setup_complete
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if parsed.path == "/server-info.action":
            setup_val = params.get(
                "bootstrapStatusProvider.applicationConfig.setupComplete", [""]
            )[0]
            if setup_val in ("0", "false"):
                if VULN_MODE:
                    with _lock:
                        _setup_complete = False
                    self._send(
                        200,
                        '{"setupComplete":false,"version":"8.5.0"}',
                        "application/json",
                    )
                else:
                    self._send(403, "Access denied", "text/plain")
            else:
                self._send(
                    200,
                    '{"version":"8.5.0","serverTitle":"Confluence"}',
                    "application/json",
                )

        elif parsed.path == "/setup/setupadministrator-start.action":
            with _lock:
                done = _setup_complete
            if done:
                self._send(200, "<html><body>Setup is already complete</body></html>")
            else:
                self._send(
                    200,
                    "<html><body>Please configure the system administrator account"
                    " for this Confluence installation</body></html>",
                )

        else:
            self._send(404, "Not found")

    def do_POST(self):
        self._read_body()
        self._send(404, "Not found")


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
