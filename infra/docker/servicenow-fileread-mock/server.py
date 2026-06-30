#!/usr/bin/env python3
import os, ssl, threading, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("SERVICENOW_MODE", "patched") == "vuln"

VULN_BODY = (
    "<html><head><title>ServiceNow</title></head><body>"
    "<div class=\"outputmsg_text\">"
    "glide.db.user=noctis_db_user\n"
    "glide.db.password=noctis_secret_pass\n"
    "glide.db.name=noctis_glide_db\n"
    "glide.db.host=localhost"
    "</div>"
    "<form action=\"/login.do\" method=\"post\">"
    "<input type=\"text\" name=\"user_name\" />"
    "</form></body></html>"
)

PATCHED_BODY = (
    "<html><head><title>ServiceNow - Log in</title></head><body>"
    "<div id=\"login-container\">"
    "<form action=\"/login.do\" method=\"post\">"
    "<input type=\"text\" name=\"user_name\" />"
    "</form></div></body></html>"
)

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/login.do":
            if VULN_MODE and "jvar_page_title" in qs:
                # Check if the payload contains the file-read Jelly pattern
                title_val = qs["jvar_page_title"][0]
                if "SecurelyAccess" in title_val or "glide.db.properties" in title_val:
                    self._send(200, VULN_BODY)
                    return
            self._send(200, PATCHED_BODY)
        else:
            self._send(404, "Not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self._send(302, b"", ct="text/plain")

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
