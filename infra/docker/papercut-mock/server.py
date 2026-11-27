#!/usr/bin/env python3
"""Mock PaperCut NG/MF — CVE-2023-27351 SecurityRequestFilter auth bypass.

Vuln mode: privileged REST endpoints suffixed with ";/keepalive" bypass the
auth filter and respond as if authenticated.
Patched mode: the ";/keepalive" trick no longer matches the allow-list, so the
privileged endpoints answer 401.
"""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("PAPERCUT_MODE", "patched") == "vuln"

VERSION = "22.0.5" if VULN_MODE else "22.0.6"

CREATE_PATH = "/rpc/api/rest/master/user/createInternalUser;/keepalive"
EXPORT_PATH = "/rpc/api/rest/master/user/getExportedUser;/keepalive"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "PaperCut")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/app":
            self._send(200, f"PaperCut MF {VERSION} - Dashboard", "text/html")
            return
        self._send(404, "Not found")

    def do_POST(self):
        path = self.path  # keep the ;/keepalive suffix intact
        # drain request body
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)

        if path == CREATE_PATH:
            if VULN_MODE:
                self._send(
                    200,
                    '{"result":"rO0ABXNyABVqYXZhLmxhbmcuU3RyaW5nVXNlcgAAAA"}',
                    "application/json",
                )
            else:
                self._send(401, '{"error":"Unauthorized"}', "application/json")
            return

        if path == EXPORT_PATH:
            if VULN_MODE:
                self._send(
                    200,
                    '{"result":"java.lang.String HASH:noctis_test!1 noctis_probe '
                    'NOCTIS_PAPERCUT_CONFIRMED"}',
                    "application/json",
                )
            else:
                self._send(401, '{"error":"Unauthorized"}', "application/json")
            return

        self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
