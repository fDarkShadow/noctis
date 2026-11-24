#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("JOBHUT_MODE", "patched") == "vuln"

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
        # browse.php — the injectable pk parameter.
        if p.startswith("/browse.php"):
            if VULN_MODE and "union" in p.lower() and "1234567" in p:
                # Vulnerable: the UNION SELECT forces the job-count value to the
                # injected sentinel (1234567), reflected in the results header.
                self._send(200,
                    "<html><body><h1>Browse Jobs</h1>"
                    "<div class='results'>Results 1-10 of 1234567 job(s) found</div>"
                    "</body></html>")
            else:
                # Patched (or benign request): a real, small job count.
                self._send(200,
                    "<html><body><h1>Browse Jobs</h1>"
                    "<div class='results'>Results 1-5 of 5 job(s) found</div>"
                    "</body></html>")
        else:
            self._send(404, "<html><body>404 Not Found</body></html>")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
