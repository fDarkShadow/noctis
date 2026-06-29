#!/usr/bin/env python3
import os, re, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import urlopen

VULN_MODE = os.environ.get("IVANTI_EPM_MODE", "patched") == "vuln"

SOAP_RESPONSE = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
    ' xmlns:xsd="http://www.w3.org/2001/XMLSchema"'
    ' xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">'
    "<soap12:Body>"
    '<UpdateStatusEventsResponse xmlns="http://tempuri.org/">'
    "<UpdateStatusEventsResult>true</UpdateStatusEventsResult>"
    "</UpdateStatusEventsResponse>"
    "</soap12:Body>"
    "</soap12:Envelope>"
)

OOB_URL_RE = re.compile(r"curl\s+(http://[^\s'<\"]+)")


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
        return self.rfile.read(length).decode("utf-8", errors="replace")

    def do_GET(self):
        self._send(
            200,
            "<html><head><title>Ivanti Endpoint Manager</title></head>"
            "<body><h1>Ivanti EPM</h1></body></html>",
        )

    def do_POST(self):
        raw = self._read_body()
        if "/WSStatusEvents/EventHandler.asmx" in self.path:
            if not VULN_MODE:
                self._send(500, b"Internal Server Error", ct="text/plain")
                return
            # Trigger OOB callback if a curl URL is present in the payload
            m = OOB_URL_RE.search(raw)
            if m:
                try:
                    urlopen(m.group(1), timeout=3)
                except Exception:
                    pass
            self._send(200, SOAP_RESPONSE, ct="application/soap+xml; charset=utf-8")
        else:
            self._send(404, b"Not Found", ct="text/plain")


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
