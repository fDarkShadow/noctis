#!/usr/bin/env python3
import os, re, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import urlopen

VULN_MODE = os.environ.get("PEOPLESOFT_MODE", "patched") == "vuln"

FP_BODY = b"PeopleSoft Integration Broker -- HttpListeningConnector active"
IB_OK = b"<IBResponse><StatusCode>0</StatusCode></IBResponse>"
SOURCE_URL_RE = re.compile(r"<sourceURL>(https?://[^<]+)</sourceURL>")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/PSIGW/HttpListeningConnector":
            if VULN_MODE:
                self._send(200, FP_BODY)
            else:
                self._send(403, b"Access denied")
        else:
            self._send(404, b"Not found")

    def do_POST(self):
        path = self.path.split("?")[0]
        if path != "/PSIGW/HttpListeningConnector":
            self._send(404, b"Not found")
            return

        if not VULN_MODE:
            self._send(403, b"Access denied")
            return

        raw = self._read_body()
        m = SOURCE_URL_RE.search(raw)
        if m:
            oob_url = m.group(1)
            try:
                urlopen(oob_url, timeout=5)
            except Exception:
                pass
        self._send(200, IB_OK, "text/xml")


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
