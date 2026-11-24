#!/usr/bin/env python3
"""Mock for CVE-2018-11523 — NUUO NVRmini 2 < 3.9.1 File Upload RCE (CVSS 7.5).

Ported from OpenVAS/Greenbone NASL 2018/nuuo/gb_nuuo_nvrmini2_file_upload_vuln.nasl
(GPL-2.0-only, Greenbone Community Feed).

Both modes serve the same NUUO NVRmini 2 product fingerprint and accept the
multipart upload to /upload.php, so the true-negative exercises a realistic,
non-vulnerable instance of the product (not a blanket 404 host).

Vuln mode: /upload.php writes the attacker's PHP file to a (simulated) web root
and PHP execution is enabled there, so a follow-up GET of the uploaded file
EXECUTES it. The marker phpinfo() page (containing "PHP Version" and "PHP API")
is emitted ONLY when the uploaded content is actually PHP that calls phpinfo()
— an empty or benign upload is stored but never produces the markers.

Patched mode: /upload.php still returns 200 (the upload endpoint exists) but PHP
execution in the upload directory is disabled, so the uploaded file is never
executed — a GET of it returns 404. No phpinfo markers -> zero findings."""
import os
import re
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("NVRMINI2_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

# Product fingerprint served on "/" in both modes (realistic TN).
LOGIN_PAGE = (
    "<html><head><title>NUUO Network Video Recorder Login</title></head>"
    "<body><h1>NUUO NVRmini2</h1><form action=\"/login.php\" method=\"post\">"
    "<input name=\"user\"><input name=\"pass\" type=\"password\">"
    "</form></body></html>"
)

# phpinfo() output emitted when an uploaded PHP webshell executes (vuln mode).
PHPINFO_PAGE = (
    "<html><head><title>phpinfo()</title></head><body>"
    "<h1 class=\"p\">PHP Version 5.4.16</h1>"
    "<table><tr><td class=\"e\">System</td><td class=\"v\">Linux nvrmini2 3.10.0</td></tr>"
    "<tr><td class=\"e\">Server API</td><td class=\"v\">CGI/FastCGI</td></tr>"
    "<tr><td class=\"e\">PHP API</td><td class=\"v\">20100412</td></tr>"
    "<tr><td class=\"e\">Zend Extension Build</td><td class=\"v\">API220100525</td></tr>"
    "</table></body></html>"
)

# filename -> True once a PHP webshell that calls phpinfo() has been uploaded
# AND execution is enabled (vuln mode only). Shared across the HTTP/HTTPS
# server threads in this process.
_UPLOADS = {}
_UPLOADS_LOCK = threading.Lock()

_FILENAME_RE = re.compile(rb'filename="([^"]+)"')


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "nuuo/NVRmini2")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(n) if n else b""

    def do_POST(self):
        body = self._read_body()
        if self.path == "/upload.php":
            m = _FILENAME_RE.search(body)
            # The product accepts the upload in both modes (endpoint exists).
            if not m:
                self._send(400, "no file part")
                return
            filename = m.group(1).decode("latin-1", "replace")
            # Only a real PHP webshell invoking phpinfo() is executable, and
            # only the vulnerable firmware executes files in the upload dir.
            is_php_shell = filename.lower().endswith(".php") and b"phpinfo" in body and b"<?php" in body
            if VULN_MODE and is_php_shell:
                with _UPLOADS_LOCK:
                    _UPLOADS[filename] = True
            self._send(200, "Upload OK")
            return
        self._send(404, "Not found")

    def do_GET(self):
        if self.path == "/" or self.path == "/index.php":
            self._send(200, LOGIN_PAGE)
            return
        name = self.path.lstrip("/")
        with _UPLOADS_LOCK:
            executable = _UPLOADS.get(name, False)
        # Vuln firmware executes the uploaded PHP -> phpinfo() markers returned.
        if VULN_MODE and executable:
            self._send(200, PHPINFO_PAGE)
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
