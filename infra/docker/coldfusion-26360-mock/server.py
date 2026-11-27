#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("COLDFUSION_MODE", "patched") == "vuln"

PASSWD_WDDX = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<wddxPacket version="1.0"><header/>'
    "<data><string>"
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "</string></data></wddxPacket>"
)

CFC_PATH = "/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/iedit.cfc"
ALT_CFC_PATH = "/CFIDE/wizards/common/utils.cfc"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _is_cfc_endpoint(self):
        return self.path.startswith(CFC_PATH) or self.path.startswith(ALT_CFC_PATH)

    def _consume_body(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)

    def do_GET(self):
        self._send(
            200,
            "<html><head><title>Adobe ColdFusion Administrator</title></head>"
            "<body><h1>ColdFusion</h1></body></html>",
        )

    def do_POST(self):
        self._consume_body()
        if self._is_cfc_endpoint():
            if VULN_MODE:
                self._send(200, PASSWD_WDDX, ct="text/xml")
            else:
                self._send(403, b"Access Denied")
        else:
            self._send(404, b"Not Found", ct="text/plain")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
