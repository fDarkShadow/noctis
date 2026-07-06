#!/usr/bin/env python3
import os, re, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("KENTICO_MODE", "patched") == "vuln"

SOAP_TEMPLATE = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
    "<soap:Body>"
    '<ProcessSynchronizationTaskResponse xmlns="http://www.kentico.com/">'
    "<ProcessSynchronizationTaskResult>{probe}</ProcessSynchronizationTaskResult>"
    "</ProcessSynchronizationTaskResponse>"
    "</soap:Body>"
    "</soap:Envelope>"
)

PROBE_RE = re.compile(r"<stagingTaskData>(.*?)</stagingTaskData>", re.DOTALL)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/xml; charset=utf-8"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""

    def do_POST(self):
        path = self.path.split("?")[0]
        if path != "/CMSPages/Staging/SyncServer.asmx":
            self._send(404, b"Not found", "text/plain")
            return

        if not VULN_MODE:
            self._send(403, b"SyncServer.ErrorLicense", "text/plain")
            return

        raw = self._read_body()
        m = PROBE_RE.search(raw)
        probe = m.group(1).strip() if m else "NOCTIS_PROBE_KENTICO_2025"
        self._send(200, SOAP_TEMPLATE.format(probe=probe))

    def do_GET(self):
        self._send(200, b"<html><body>Kentico Xperience</body></html>", "text/html")


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
