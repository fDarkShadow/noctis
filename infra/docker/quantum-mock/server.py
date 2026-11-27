#!/usr/bin/env python3
"""Mock Quantum Scalar i500 / Dell ML6000 / IBM TS3310 web UI.

CVE-2012-1841 / CVE-2012-1842 / CVE-2012-1844 — unauthenticated arbitrary file
read through the /logShow.htm log viewer.

Both modes serve the appliance login page at /index.htm (identifying <title>),
so the detection's stage-1 gate matches either way — the appliance still exists
after patching. Vuln mode additionally leaks an arbitrary file via
/logShow.htm?file=/<path> (here /etc/passwd). Patched mode 404s /logShow.htm, so
no file content is returned and the scan yields zero findings.
"""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("QUANTUM_MODE", "patched") == "vuln"

LOGIN_PAGE = (
    "<html><head><title>QUANTUM - Scalar i500</title></head>"
    "<body>Login Screen</body></html>"
)

PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # self.path keeps the raw request-target (query + any %xx) intact.
        if self.path == "/index.htm":
            self._send(200, LOGIN_PAGE)
            return
        # /logShow.htm?file=/<path> — arbitrary file read (vuln only).
        if self.path.startswith("/logShow.htm"):
            if VULN_MODE and "file=" in self.path:
                self._send(200, PASSWD, ct="text/plain")
            else:
                self._send(404, "Not Found")
            return
        self._send(404, "Not Found")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
