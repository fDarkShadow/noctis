#!/usr/bin/env python3
import os, re, ssl, threading, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("PENTAHO_MODE", "patched") == "vuln"


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

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        if path != "/pentaho/api/ldap/config/ldapTreeNodeChildren/require.js":
            self._send(404, "Not found", "text/plain")
            return

        if not VULN_MODE:
            self._send(403, '{"message":"Not authorized"}')
            return

        url_param = params.get("url", [""])[0]

        # OOB path: SpEL expression with newInstance — extract and call back
        match = re.search(r'newInstance\("(http://[^"]+)"\)', url_param)
        if match:
            oob_url = match.group(1)
            try:
                urllib.request.urlopen(oob_url, timeout=5)
            except Exception:
                pass
            self._send(200, '{"LDAP Error":"Connection refused"}')
            return

        # Fingerprint path: simple URL probe
        host = urllib.parse.quote(url_param) if url_param else "unknown"
        self._send(200, '{"LDAP Error":"Could not connect to ' + host + ':389"}')

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
