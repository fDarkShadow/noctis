#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from mocklib import serve

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


if __name__ == "__main__":
    serve(Handler, HTTPServer)
