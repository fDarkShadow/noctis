#!/usr/bin/env python3
import os, re, ssl, threading, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("BEYONDTRUST_MODE", "patched") == "vuln"

LOGIN_PAGE = "<html><title>BeyondTrust Remote Support</title><body>BeyondTrust login</body></html>"
VULN_VER_BODY = '{"version":"24.3.1","product":"BeyondTrust Remote Support","status":"Thank you for using BeyondTrust"}'
PATCHED_VER_BODY = '{"version":"24.4.0","product":"BeyondTrust Remote Support","status":"Thank you for using BeyondTrust"}'

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
        if self.path in ("/login", "/"):
            self._send(200, LOGIN_PAGE)
        elif self.path.startswith("/get_rdf"):
            body = VULN_VER_BODY if VULN_MODE else PATCHED_VER_BODY
            self._send(200, body, "application/json")
        else:
            self._send(404, "Not found")

    def do_POST(self):
        if self.path == "/get_gskey":
            if not VULN_MODE:
                self._send(403, "Forbidden")
                return
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8", errors="replace")
            body_decoded = urllib.parse.unquote_plus(body)
            m = re.search(r"curl\s+(https?://[^\s&]+)", body_decoded)
            if m:
                url = m.group(1).rstrip("\r\n -")
                try:
                    urllib.request.urlopen(url, timeout=5)
                except Exception:
                    pass
            self._send(200, "OK")
        else:
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
