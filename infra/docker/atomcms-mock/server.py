#!/usr/bin/env python3
"""Mock Digital Craft AtomCMS server — CVE-2014-4852 (file upload + SQLi).

Both modes serve a realistic AtomCMS fingerprint: `index.php` advertises the
product/version and `/admin/uploads.php` renders the admin uploads table (which
contains the NASL extra_check markers "id" and ">Table").

Vulnerable mode additionally reflects the backend "UPDATE users SET avatar"
statement in an error-based double-query response, but ONLY when the real
injection payload (the `floor(rand(0)*2)` double-query signature against
`information_schema`) is present in the `id` parameter. A benign `id` is handled
normally, so the true-positive proves the payload matters.

Patched mode serves the identical admin uploads page but never leaks the SQL
statement, so a genuine, product-serving instance produces zero findings.
"""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("ATOMCMS_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

# Signature of the real error-based double-query injection the NASL sends.
INJECTION_MARKERS = ("floor(rand(0)*2)", "information_schema")

# Product fingerprint served by both modes (NASL greps "AtomCMS ([0-9.]+)<").
INDEX_PAGE = (
    "<html><head><title>AtomCMS</title></head><body>"
    "<h1>Powered by AtomCMS 1.0<</h1>"
    "<p>Digital Craft Content Management System</p>"
    "</body></html>"
)


def _uploads_page(extra=""):
    """Admin uploads listing. Contains the NASL extra_check markers id/>Table."""
    return (
        "<html><head><title>AtomCMS :: Uploads</title></head><body>"
        "<h2>AtomCMS Admin &mdash; Uploads</h2>"
        "<table class=\"uploads\"><thead><tr>"
        "<th>id</th><th>Table</th><th>File</th><th>Avatar</th>"
        "</tr></thead><tbody>"
        "<tr><td>1</td><td>users</td><td>avatar.php</td><td>avatar.png</td></tr>"
        "</tbody></table>"
        + extra +
        "</body></html>"
    )


# Error-based leak: the injected subquery forces the backend to echo the
# offending UPDATE statement alongside the resolved database() name.
SQL_LEAK = (
    "<pre class=\"sql-error\">"
    "You have an error in your SQL syntax; the query was: "
    "UPDATE users SET avatar='avatar.php' WHERE id=1 "
    "-- Duplicate entry '~'atomcms'~1' for key 'group_key'"
    "</pre>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ct="text/html", extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "Apache/2.2.22 (Ubuntu)")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path
        if path == "/" or path.startswith("/index.php"):
            self._send(200, INDEX_PAGE)
            return
        if path.startswith("/admin/uploads.php"):
            injected = "id=" in path and all(m in path for m in INJECTION_MARKERS)
            if VULN_MODE and injected:
                # Only the real injection triggers the error-based leak.
                self._send(200, _uploads_page(extra=SQL_LEAK))
            else:
                # Benign request (or patched instance) → normal admin page.
                self._send(200, _uploads_page())
            return
        self._send(404, "<html><body>Not Found</body></html>")

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
            daemon=True).start()
    if PORT_HTTP:
        HTTPServer(("0.0.0.0", PORT_HTTP), Handler).serve_forever()
    else:
        threading.Event().wait()
