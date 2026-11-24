#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("APPRAIN_MODE", "patched") == "vuln"

# Bounded marker reflected by the injected CONCAT() column, per the OpenVAS
# plugin: ov-sql-inj-test:<@@version>:ov-sql-inj-test. The mock reflects it ONLY
# when the request carries the CONCAT(0x6f762d... payload (not self-fulfilling).
MARKER = "ov-sql-inj-test:5.5.40-log:ov-sql-inj-test"
PAYLOAD_SIG = "concat(0x6f762d"

# appRain fingerprint — served in both modes (NASL: 200 + "Start with appRain<"
# and extra_check ">Profile").
FINGERPRINT = "<h1>Profile</h1><p>Start with appRain</p>"

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
        # Profile endpoint — fingerprint request and injectable SQLi sink.
        if p.startswith("/profile/"):
            if VULN_MODE and PAYLOAD_SIG in p.lower():
                # Vulnerable: the injected CONCAT() column reflects the marker.
                self._send(200,
                    "<html><body>%s"
                    "<div class='profile-field'>%s</div>"
                    "</body></html>" % (FINGERPRINT, MARKER))
            else:
                # Fingerprint page (both modes) / patched: appRain profile, no marker.
                self._send(200, "<html><body>%s</body></html>" % FINGERPRINT)
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
