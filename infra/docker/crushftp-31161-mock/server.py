#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

VULN_MODE = os.environ.get("CRUSHFTP_MODE", "patched") == "vuln"

USER_LIST_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<user_list>'
    '<user_list_subitem>crushadmin</user_list_subitem>'
    '</user_list>'
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

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
        if parsed.path == "/WebInterface/function/":
            params = parse_qs(parsed.query)
            if params.get("command") == ["getUserList"]:
                auth = self.headers.get("Authorization", "")
                cookie = self.headers.get("Cookie", "")
                if (
                    VULN_MODE
                    and auth.startswith("AWS4-HMAC-SHA256 Credential=crushadmin/")
                    and "CrushAuth=" in cookie
                    and "currentAuth=" in cookie
                ):
                    self._send(200, USER_LIST_XML, "text/xml")
                else:
                    self._send(401, "Unauthorized")
            else:
                self._send(401, "Unauthorized")
        else:
            self._send(404, "Not Found")

    def do_POST(self):
        self._send(404, "Not Found")


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
