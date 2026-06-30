#!/usr/bin/env python3
import os, re, ssl, threading, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

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
