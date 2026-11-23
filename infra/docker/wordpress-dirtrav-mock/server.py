#!/usr/bin/env python3
# Mock for WordPress Multiple Plugins / Themes Directory Traversal / File Download
# (CVE-2007-6369). Vuln mode: the vulnerable plugin download endpoint honours a
# traversal payload in the `file` POST parameter and returns wp-config.php
# (leaking DB_NAME). Patched mode: the endpoint rejects traversal (404).
import os, ssl, threading, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("WORDPRESS_DIRTRAV_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

WP_CONFIG = (
    "<?php\n"
    "/** The name of the database for WordPress */\n"
    "define( 'DB_NAME', 'wordpress_db' );\n"
    "define( 'DB_USER', 'wp_user' );\n"
    "define( 'DB_PASSWORD', 's3cr3t_pw' );\n"
    "define( 'DB_HOST', 'localhost' );\n"
    "$table_prefix = 'wp_';\n"
)

DOWNLOAD_PATH = "/wp-content/plugins/db-backup/download.php"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, body, ct="text/plain", extra_headers=None):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items(): self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == DOWNLOAD_PATH:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length).decode("latin-1") if length else ""
            params = urllib.parse.parse_qs(raw)
            # URL-decoded file parameter, e.g. ../../../../wp-config.php
            file_val = (params.get("file") or [""])[0]
            if VULN_MODE and "wp-config.php" in file_val and (".." in file_val or "/" in file_val):
                self._send(200, WP_CONFIG, ct="application/octet-stream")
                return
            # Patched: traversal blocked.
            self._send(404, "Not found")
            return
        self._send(404, "Not found")

    def do_GET(self):
        self._send(404, "Not found")


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(CERT_DIR, "server.crt"), os.path.join(CERT_DIR, "server.key"))
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    if PORT_HTTPS:
        threading.Thread(target=lambda: _make_https_server(PORT_HTTPS).serve_forever(), daemon=True).start()
    if PORT_HTTP:
        HTTPServer(("0.0.0.0", PORT_HTTP), Handler).serve_forever()
    else:
        threading.Event().wait()
