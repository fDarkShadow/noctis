#!/usr/bin/env python3
import json, os, re, ssl, threading, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("WHATSUPGOLD_MODE", "patched") == "vuln"

SOAP_OK = (
    '<?xml version="1.0"?>'
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
    '<soap:Body>'
    '<TestRecurringReportResponse xmlns="http://tempuri.org/">'
    '<TestRecurringReportResult>0</TestRecurringReportResult>'
    '</TestRecurringReportResponse>'
    '</soap:Body>'
    '</soap:Envelope>'
)

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
        return self.rfile.read(length).decode("utf-8", errors="replace") if length else ""

    def do_POST(self):
        if self.path.startswith("/NmAPI/RecurringReport"):
            if not VULN_MODE:
                self._read_body()
                self._send(401, "Unauthorized")
                return
            body = self._read_body()
            m = re.search(r'<a:URL[^>]*>([^<]+)</a:URL>', body)
            if m:
                try:
                    data = json.loads(m.group(1))
                    base_url = data.get("baseUrl", "")
                    if base_url:
                        # baseUrl is the full OOB URL with token — fetch it directly
                        threading.Thread(target=_fetch_url, args=(base_url,), daemon=True).start()
                except (json.JSONDecodeError, KeyError):
                    pass
            self._send(200, SOAP_OK, "text/xml; charset=utf-8")
        else:
            self._send(404, "Not found")

    def do_GET(self):
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
