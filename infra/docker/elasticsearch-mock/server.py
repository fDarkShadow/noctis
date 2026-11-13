#!/usr/bin/env python3
"""Minimal Elasticsearch mock for the unauthenticated-exposure check.

vuln:    GET / returns the ES cluster banner JSON ("You Know, for Search")
         without any credentials.
patched: security enabled -> GET / returns 401 with a security_exception and
         never the banner.

Serves HTTP:80 and HTTPS:443 (self-signed cert generated at build time).
"""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("ES_MODE", "patched") == "vuln"

BANNER = (
    '{\n'
    '  "name" : "noctis-node-1",\n'
    '  "cluster_name" : "noctis-cluster",\n'
    '  "cluster_uuid" : "aQbCdEf0GhIjKlMnOpQrSt",\n'
    '  "version" : {\n'
    '    "number" : "8.11.1",\n'
    '    "build_flavor" : "default",\n'
    '    "lucene_version" : "9.8.0"\n'
    '  },\n'
    '  "tagline" : "You Know, for Search"\n'
    '}\n'
)

UNAUTHORIZED = (
    '{"error":{"root_cause":[{"type":"security_exception",'
    '"reason":"missing authentication credentials for REST request [/]"}],'
    '"type":"security_exception",'
    '"reason":"missing authentication credentials for REST request [/]"},'
    '"status":401}'
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        if code == 401:
            self.send_header("WWW-Authenticate", 'Basic realm="security"')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if VULN_MODE and self.path == "/":
            self._send(200, BANNER)
        else:
            self._send(401, UNAUTHORIZED)

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
