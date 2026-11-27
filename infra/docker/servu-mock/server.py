#!/usr/bin/env python3
import os, ssl, threading, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("SERVU_MODE", "patched") == "vuln"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Server", "Serv-U")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        internal_dir = params.get("InternalDir", [""])[0]
        internal_file = params.get("InternalFile", [""])[0]

        if VULN_MODE and ".." in internal_dir:
            if internal_file.lower() == "passwd":
                self._send(200, "root:x:0:0:root:/root:/bin/bash\nnoctis:x:1000:1000::/home/noctis:/bin/sh\n")
            elif internal_file.lower() == "win.ini":
                self._send(200, "[fonts]\r\n[extensions]\r\n[mci extensions]\r\n")
            else:
                self._send(200, "noctis_servu_file_content")
        else:
            self._send(400, "Bad Request")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
