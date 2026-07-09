#!/usr/bin/env python3
import json, os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("CYBERPANEL_MODE", "patched") == "vuln"

RCE_BODY = json.dumps({
    "error_message": "",
    "requestStatus": "OK",
    "output": "uid=0(root) gid=0(root) groups=0(root)",
}, separators=(',', ':')).encode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="application/json"):
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
        self._send(200, b"<html><title>CyberPanel</title><body>CyberPanel</body></html>", "text/html")

    def do_PUT(self):
        path = self.path.split("?")[0]
        if "upgrademysqlstatus" not in path:
            self._send(404, b"Not found")
            return

        if not VULN_MODE:
            self._send(403, b'{"error":"CSRF token required or authentication needed"}')
            return

        self._read_body()
        self._send(200, RCE_BODY)

    def do_POST(self):
        self._send(403, b'{"error":"Authentication required"}')


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
