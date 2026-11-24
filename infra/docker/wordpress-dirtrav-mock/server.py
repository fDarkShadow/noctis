#!/usr/bin/env python3
# Mock for WordPress Multiple Plugins / Themes Directory Traversal / File Download
# (combined OpenVAS NVT; representative endpoint: db-backup plugin download.php).
#
# Both modes serve the same WordPress product fingerprint (the site front page and
# the plugin's download.php endpoint exist in both).
#
#   Vuln mode    : download.php honours a traversal payload in the `file` query
#                  parameter and leaks the requested host file — wp-config.php
#                  (DB_NAME/DB_USER/DB_PASSWORD) or /etc/passwd. The leak happens
#                  ONLY when the request actually carries a traversal payload
#                  (a `..` sequence), so the true-positive proves the payload
#                  matters — not that the mock echoes a marker unconditionally.
#   Patched mode : the SAME endpoint exists and returns HTTP 200, but the fixed
#                  plugin strips the path to its basename, so a traversal request
#                  never escapes the backup directory and the secret is never
#                  disclosed (no blanket 404 — the product is served realistically).
import os, ssl, threading, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("WORDPRESS_DIRTRAV_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

DOWNLOAD_PATH = "/wp-content/plugins/db-backup/download.php"

# Leaked host files the traversal can reach.
WP_CONFIG = (
    "<?php\n"
    "/** The name of the database for WordPress */\n"
    "define( 'DB_NAME', 'wordpress_db' );\n"
    "define( 'DB_USER', 'wp_user' );\n"
    "define( 'DB_PASSWORD', 's3cr3t_pw' );\n"
    "define( 'DB_HOST', 'localhost' );\n"
    "$table_prefix = 'wp_';\n"
)
ETC_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
)

# A realistic WordPress front page, served identically in both modes.
FRONT_PAGE = (
    "<!DOCTYPE html>\n<html><head><meta name=\"generator\" content=\"WordPress 5.8\">"
    "<title>My WordPress Site</title></head><body>"
    "<div id=\"content\">Welcome to WordPress.</div></body></html>\n"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, body, ct="text/html", extra_headers=None):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items(): self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _serve_leak(self, file_val):
        # Decide which host file the traversal resolves to.
        if "wp-config.php" in file_val:
            self._send(200, WP_CONFIG, ct="application/octet-stream",
                       extra_headers={"Content-Disposition": "attachment; filename=\"wp-config.php\""})
        elif "passwd" in file_val:
            self._send(200, ETC_PASSWD, ct="application/octet-stream",
                       extra_headers={"Content-Disposition": "attachment; filename=\"passwd\""})
        else:
            # Some other traversal target — unknown to the mock.
            self._send(200, "", ct="application/octet-stream")

    def _handle_download(self, file_val):
        has_traversal = ".." in file_val
        if VULN_MODE and file_val and has_traversal:
            # Vulnerable: path is used unsanitised → traversal escapes the dir.
            self._serve_leak(file_val)
            return
        # Patched (or a non-traversal request on the vuln mock): the fixed plugin
        # reduces `file` to its basename, so no secret is disclosed. Product-realistic
        # 200 with a backup listing, never the leaked file.
        self._send(200, "Backup not found.\n")

    def _file_param(self):
        parsed = urllib.parse.urlsplit(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        return (params.get("file") or [""])[0], parsed.path

    def do_GET(self):
        file_val, path = self._file_param()
        if path == DOWNLOAD_PATH:
            self._handle_download(file_val)
            return
        if path in ("/", "/index.php", "/wp-login.php"):
            self._send(200, FRONT_PAGE)
            return
        self._send(404, "Not found")

    def do_POST(self):
        # The plugin reads $_GET['file']; a POST to the endpoint behaves the same
        # (query string still honoured), but never leaks on its own.
        file_val, path = self._file_param()
        if path == DOWNLOAD_PATH:
            self._handle_download(file_val)
            return
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
