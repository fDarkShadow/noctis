#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("CLIPBUCKET_MODE", "patched") == "vuln"

MARKER = "SQL-Injection-Test"

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
        # Page view endpoint — the injectable pid parameter.
        if p.startswith("/view_page.php"):
            if VULN_MODE and "union" in p.lower() and "pid=0%27" in p.lower():
                # Vulnerable: the UNION SELECT reflects the marker column into the page.
                self._send(200,
                    "<html><body><h1>Page</h1>"
                    "<div class='page-title'>%s<br/></div>"
                    "<a href='login.php'>Login</a></body></html>" % MARKER)
            else:
                # Patched (or benign request): normal page, no reflection.
                self._send(200,
                    "<html><body><h1>Page</h1>"
                    "<p>Page not available.</p>"
                    "<a href='login.php'>Login</a></body></html>")
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
