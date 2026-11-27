#!/usr/bin/env python3
import os, ssl, threading, json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
from mocklib import serve

VULN_MODE = os.environ.get("JOOMLA_MODE", "patched") == "vuln"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/index.php/v1/config/application":
            if VULN_MODE:
                data = json.dumps({
                    "links": {"self": "http://target/api/index.php/v1/config/application"},
                    "attributes": {
                        "db": "joomla",
                        "dbtype": "mysqli",
                        "host": "localhost",
                        "user": "joomla_user",
                        "password": "NOCTIS_JOOMLA_SECRET",
                        "dbprefix": "jos_",
                        "secret": "abc123"
                    }
                })
                self._send(200, data)
            else:
                self._send(401, "{}")
        else:
            self._send(404, json.dumps({"error": "Not found"}))

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
