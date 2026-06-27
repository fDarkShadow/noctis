#!/usr/bin/env python3
import json
import os
import ssl
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("DRUPAL_MODE", "vuln") == "vuln"

SQLSTATE_RESP = json.dumps({
    "errors": [{
        "title": "Internal Server Error",
        "detail": "SQLSTATE[HY000]: General error: 1 no such column: `",
        "status": "500"
    }]
}).encode()

UNRECOGNIZED_RESP = json.dumps({
    "message": "unrecognized name format in SQL query"
}).encode()

JSONAPI_400 = json.dumps({
    "errors": [{"title": "Bad Request", "detail": "Invalid filter value.", "status": "400"}]
}).encode()

LOGIN_422 = json.dumps({
    "message": "Unprocessable Entity: validation failed."
}).encode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, content_type="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        if path in ("/jsonapi/node/article", "/jsonapi/node/page"):
            # Check for backtick in filter value keys (URL-decoded automatically by parse_qs)
            raw_qs = urllib.parse.unquote(parsed.query)
            if VULN_MODE and "`" in raw_qs:
                self._send(500, SQLSTATE_RESP)
            else:
                self._send(400, JSONAPI_400)
        else:
            self._send(404, b'{"message":"Not Found"}')

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body_raw = self._read_body()

        if path == "/user/login":
            if not VULN_MODE:
                self._send(422, LOGIN_422)
                return

            try:
                data = json.loads(body_raw)
                name = data.get("name", "")
                # Detect if name is a dict (JSON object) containing SQL injection keys
                if isinstance(name, dict):
                    keys_str = " ".join(name.keys())
                    # True condition: 1=1 → return 500
                    if "1=1" in keys_str:
                        self._send(500, json.dumps({"message": "internal server error"}).encode())
                    # False condition: 1=2 → return 400 with unrecognized
                    elif "1=2" in keys_str:
                        self._send(400, UNRECOGNIZED_RESP)
                    else:
                        self._send(422, LOGIN_422)
                else:
                    self._send(422, LOGIN_422)
            except (json.JSONDecodeError, Exception):
                self._send(422, LOGIN_422)
        else:
            self._send(404, b'{"message":"Not Found"}')


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/cert/server.crt", "/cert/server.key")
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    http_srv = HTTPServer(("0.0.0.0", 80), Handler)
    https_srv = _make_https_server(443)
    threading.Thread(target=https_srv.serve_forever, daemon=True).start()
    http_srv.serve_forever()
