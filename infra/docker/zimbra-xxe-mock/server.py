#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("ZIMBRA_XXE_MODE", "patched") == "vuln"

AUTODISCOVER_PATH = "/autodiscover/autodiscover.xml"

PASSWD_BODY = (
    b'<?xml version="1.0"?>'
    b'<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">'
    b"<Response><User><EMailAddress>"
    b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    b"</EMailAddress></User></Response></Autodiscover>"
)

SAFE_BODY = (
    b'<?xml version="1.0"?>'
    b"<Autodiscover><Response><Error>XXE not supported</Error></Response></Autodiscover>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/xml"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def do_POST(self):
        path = self.path.split("?")[0]
        if path.lower() != AUTODISCOVER_PATH:
            self._send(404, b"Not found")
            return

        raw = self._read_body()

        if VULN_MODE and (b"file:///etc/passwd" in raw or b"ENTITY xxe" in raw):
            self._send(200, PASSWD_BODY)
        else:
            self._send(200, SAFE_BODY)

    def do_GET(self):
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
