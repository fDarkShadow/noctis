#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("WHD_MODE", "patched") == "vuln"

# helpdeskIntegrationUser:dev-C4F8025E7
HARDCODED_AUTH = "Basic aGVscGRlc2tJbnRlZ3JhdGlvblVzZXI6ZGV2LUM0RjgwMjVFNw=="

TICKET_JSON = (
    '[{"displayClient":"Test Client","shortDetail":"Password reset request",'
    '"id":1,"status":"open"}]'
)
UNAUTH = '{"error":"Unauthorized"}'

WHD_PATH = "/helpdesk/WebObjects/Helpdesk.woa/ra/OrionTickets/"


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
        if self.path == WHD_PATH:
            auth = self.headers.get("Authorization", "")
            if VULN_MODE and auth == HARDCODED_AUTH:
                self._send(200, TICKET_JSON)
            else:
                self._send(401, UNAUTH)
        else:
            self._send(404, '{"error":"Not found"}')

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
