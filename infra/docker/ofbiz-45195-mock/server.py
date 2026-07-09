#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("OFBIZ_45195_MODE", "patched") == "vuln"

ENTITY_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<entity-engine-xml>
<UserLogin partyId="admin" currentPassword="$SHA$noctis$NOCTIS_CHECK" enabled="Y" requirePasswordChange="N"/>
</entity-engine-xml>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body=b"", ct="text/plain", location=None):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        if location:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/common/noctischeck.txt":
            if VULN_MODE:
                self._send(200, ENTITY_XML, "text/xml")
            else:
                self._send(404, b"Not found")
        else:
            self._send(404, b"Not found")

    def do_POST(self):
        path = self.path.split("?")[0]
        if "xmldsdump" in path:
            if VULN_MODE:
                self._send(200, b"OK")
            else:
                self._send(302, location="/webtools/control/main")
        else:
            self._send(404, b"Not found")


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
