#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("ARTICLEFR_MODE", "patched") == "vuln"

# ArticleFR fingerprint — served in both modes (NASL probes only an ArticleFR
# install). The version reflection below is server-computed (version()), not
# echoed from the URL.
FINGERPRINT = '<meta name="generator" content="ArticleFR CMS">'

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
        # rate.php — the injectable 'id' parameter of the rating endpoint.
        if p.startswith("/rate.php") and "act=set" in p:
            if VULN_MODE and "union" in p.lower() and "id=0" in p.lower():
                # Vulnerable: the UNION SELECT reflects version() into the
                # rating response -> matches scored.*from.([0-9.]+)
                self._send(200,
                    "<html><head>%s</head><body>"
                    "<div class=\"rating\">Already scored. Result from 5.5.38</div>"
                    "</body></html>" % FINGERPRINT)
            else:
                # Patched (or benign request): normal rating ack, no reflection.
                self._send(200,
                    "<html><head>%s</head><body>"
                    "<div class=\"rating\">Thanks for rating.</div></body></html>" % FINGERPRINT)
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
