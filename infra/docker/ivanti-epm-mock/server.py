#!/usr/bin/env python3
import os, ssl, threading, json
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("IVANTI_EPM_MODE", "patched") == "vuln"

AUTH_SUCCESS = json.dumps({
    "sessionid": "a1b2c3d4e5f6789012345678901234567890",
    "username": "administrator"
})

AUTH_DENIED = json.dumps({
    "sessionid": None,
    "error": "Authentication required"
})


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""

    def do_POST(self):
        body = self._read_body()
        if self.path.startswith("/RemoteControlAuth/api/Auth"):
            try:
                data = json.loads(body)
                if data.get("logintype") == "64" and VULN_MODE:
                    self._send(200, AUTH_SUCCESS)
                else:
                    self._send(200, AUTH_DENIED)
            except (json.JSONDecodeError, AttributeError):
                self._send(400, json.dumps({"error": "Invalid request"}))
        else:
            self._send(404, json.dumps({"error": "Not found"}))

    def do_GET(self):
        self._send(404, json.dumps({"error": "Not found"}))


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
