#!/usr/bin/env python3
import os, re, ssl, threading, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("EPMM_MODE", "patched") == "vuln"

SSTI_BODY = b'{"error":"Bad Request","localizedMessage":"Format \'Process[pid=1]\' is invalid for featureusage_history","requestStatus":"FAILURE"}'
AUTH_FAIL = b'{"error":"Unauthorized","requestStatus":"FAILURE"}'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if "featureusage" not in path:
            self._send(404, b"Not found", "text/plain")
            return

        if not VULN_MODE:
            self._send(401, AUTH_FAIL)
            return

        params = urllib.parse.parse_qs(parsed.query)
        fmt = params.get("format", [""])[0]

        # OOB path: format contains curl command → extract URL and call back
        curl_match = re.search(r"exec\('curl\s+(http://[^']+)'", fmt)
        if curl_match:
            oob_url = curl_match.group(1)
            try:
                urllib.request.urlopen(oob_url, timeout=5)
            except Exception:
                pass
            self._send(400, SSTI_BODY)
            return

        # SSTI error-based detection path
        if fmt and ("java.lang.Runtime" in fmt or "exec(" in fmt):
            self._send(400, SSTI_BODY)
            return

        # Normal response
        self._send(200, b'{"data":[],"requestStatus":"SUCCESS"}')

    def do_POST(self): self.do_GET()


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
