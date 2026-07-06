#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("OIM_MODE", "patched") == "vuln"

GROOVY_PATH = "/iam/governance/applicationmanagement/api/v1/applications/groovyscriptstatus"
AUTH_BODY = b'{"errorCode":"401","errorMessage":"Authentication required"}'
BYPASS_BODY = b'{"status":"success","message":"Script Compilation Successful","output":"NOCTIS_OIM_PROBE_2025"}'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="application/json", extra_headers=None):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "Oracle/12.2.1.4")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def do_GET(self):
        path = self.path.split("?")[0]
        if GROOVY_PATH in path:
            self._send(401, AUTH_BODY)
        else:
            self._send(404, b"Not found")

    def do_POST(self):
        path = self.path.split("?")[0]
        if GROOVY_PATH not in path:
            self._send(404, b"Not found")
            return

        self._read_body()

        if VULN_MODE and ";.wadl" in path:
            self._send(200, BYPASS_BODY)
        else:
            self._send(401, AUTH_BODY)


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
