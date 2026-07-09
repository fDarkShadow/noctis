#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("YII2_MODE", "patched") == "vuln"

FP_BODY = b"<html><title>Yii Application</title><body>Yii Framework v2.0.51</body></html>"

PHPINFO_BODY = b"""<html><body>
<h1>PHP Version 8.1.27</h1>
<table>
<tr><td class="e">PHP Extension</td><td class="v">json, mbstring, openssl</td></tr>
<tr><td class="e">System</td><td class="v">Linux noctis-mock 5.15.0</td></tr>
</table></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def do_GET(self):
        self._send(200, FP_BODY)

    def do_POST(self):
        path = self.path.split("?")[0]
        raw = self._read_body()

        if "index.php" not in path:
            self._send(404, b"Not found")
            return

        if not VULN_MODE:
            self._send(400, b'{"error": "Invalid input: __class key not allowed"}', "application/json")
            return

        if b"FnStream" in raw and b"phpinfo" in raw:
            self._send(200, PHPINFO_BODY)
        else:
            self._send(200, FP_BODY)


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
