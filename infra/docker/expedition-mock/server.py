#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote_plus, parse_qs

VULN_MODE = os.environ.get("EXPEDITION_MODE", "patched") == "vuln"

ENDPOINT = "/API/convertCSVtoParquet.php"

VULN_BODY = (
    b"PHP Notice:  Undefined index: taskID in "
    b"/var/www/html/API/convertCSVtoParquet.php on line 37\n"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Server", "Apache")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(200, b"<html><body><h1>Palo Alto Networks Expedition</h1></body></html>")

    def do_POST(self):
        if self.path == ENDPOINT:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
            params = parse_qs(raw, keep_blank_values=True)
            ram = params.get("ram", [""])[0]
            if VULN_MODE and ("`" in ram or "$(" in ram):
                self._send(200, VULN_BODY)
            elif VULN_MODE:
                self._send(200, b"")
            else:
                self._send(403, b"Forbidden", "text/plain")
        else:
            self._send(404, b"Not found", "text/plain")


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
