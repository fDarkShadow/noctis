#!/usr/bin/env python3
import os, re, ssl, threading, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("SAP_NW_MODE", "patched") == "vuln"

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
        return self.rfile.read(length).decode("latin-1") if length else ""

    def do_GET(self):
        if self.path.startswith("/developmentserver/"):
            if VULN_MODE:
                self._send(200, "SAP NetWeaver Visual Composer developmentserver endpoint")
            else:
                self._send(403, "Forbidden")
        else:
            self._send(404, "Not found")

    def do_POST(self):
        if self.path.startswith("/developmentserver/metadatauploader"):
            if not VULN_MODE:
                self._read_body()
                self._send(403, "Forbidden")
                return
            body = self._read_body()
            m = re.search(r'https?://[^\s\r\n"\'\\]+', body)
            if m:
                url = m.group(0)
                threading.Thread(target=_fetch_url, args=(url,), daemon=True).start()
            self._send(200, "FAILED\nCause: com.sap.cts.metadata.validation.MetadataValidationException")
        else:
            self._send(404, "Not found")

def _fetch_url(url):
    try:
        urllib.request.urlopen(url, timeout=10)
    except Exception:
        pass


if __name__ == "__main__":
    serve(Handler, HTTPServer)
