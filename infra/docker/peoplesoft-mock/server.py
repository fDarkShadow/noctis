#!/usr/bin/env python3
import os, re, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import urlopen
from mocklib import serve

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


if __name__ == "__main__":
    serve(Handler, HTTPServer)
