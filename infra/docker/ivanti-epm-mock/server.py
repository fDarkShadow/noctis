#!/usr/bin/env python3
import json, os, re, ssl, threading, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("IVANTI_EPM_MODE", "patched") == "vuln"

AUTH_SUCCESS = json.dumps({
    "sessionid": "a1b2c3d4e5f6789012345678901234567890",
    "username": "administrator"
})

AUTH_DENIED = json.dumps({
    "sessionid": None,
    "error": "Authentication required"
})

# CVE-2024-29824 — UpdateStatusEvents SOAP action accepts the stacked SQLi
# payload and would execute it via xp_cmdshell on a real vulnerable server.
SOAP_RESPONSE = """<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
<soap12:Body><UpdateStatusEventsResponse xmlns="http://tempuri.org/"><UpdateStatusEventsResult>true</UpdateStatusEventsResult></UpdateStatusEventsResponse></soap12:Body>
</soap12:Envelope>"""


def _fetch_url(url):
    try:
        urllib.request.urlopen(url, timeout=10)
    except Exception:
        pass


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""

    def do_POST(self):
        body = self._read_body()
        if self.path.startswith("/RemoteControlAuth/api/Auth"):
            try:
                data = json.loads(body)
                if data.get("logintype") == "64" and VULN_MODE:
                    self._send(200, AUTH_SUCCESS)
                else:
                    self._send(200, AUTH_DENIED)
            except (json.JSONDecodeError, AttributeError):
                self._send(400, json.dumps({"error": "Invalid request"}))
        elif self.path.startswith("/WSStatusEvents/EventHandler.asmx"):
            if VULN_MODE:
                m = re.search(r"curl\s+(https?://[^\s'\"]+)", body)
                if m:
                    threading.Thread(target=_fetch_url, args=(m.group(1),), daemon=True).start()
                self._send(200, SOAP_RESPONSE, "text/xml; charset=utf-8")
            else:
                self._send(404, json.dumps({"error": "Not found"}))
        else:
            self._send(404, json.dumps({"error": "Not found"}))

    def do_GET(self):
        self._send(404, json.dumps({"error": "Not found"}))


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
