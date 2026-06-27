#!/usr/bin/env python3
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

VULN_MODE = os.environ.get("TEAMCITY_MODE", "patched") == "vuln"

SERVER_XML = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    b'<server version="2023.11.3" buildNumber="123456" versionMajor="2023"'
    b' versionMinor="11" internalId="abc-def-123456" role="SERVER_NODE"/>'
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        jsp = qs.get("jsp", [""])[0]

        is_bypass = parsed.path == "/hax" and "/app/rest/server" in jsp
        is_direct = parsed.path == "/app/rest/server"

        if is_bypass or is_direct:
            if VULN_MODE:
                self._send(200, SERVER_XML, "application/xml")
            else:
                self._send(401, b"Authentication required")
        else:
            self._send(404, b"Not found")

    def do_POST(self):
        self.do_GET()


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/certs/server.crt", "/certs/server.key")
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    mode = "vuln" if VULN_MODE else "patched"
    print(f"TeamCity mock on :80/:443 (mode={mode})", flush=True)
    https = _make_https_server(443)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
