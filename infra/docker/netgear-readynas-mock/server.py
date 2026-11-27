#!/usr/bin/env python3
"""Mock NetGear ReadyNAS RAIDiator FrontView — CVE-2013-2751 / CVE-2013-2752.

Both modes:
  * GET /np_handler/ returns the FrontView handler marker "Empty No Support".
    This endpoint is only a precondition — a patched ReadyNAS still serves it.
Vuln mode only:
  * GET /np_handler/np_handler.pl?...addr=...`id`... (the command-injection
    payload) reflects the executed command output (uid=.../gid=...).
Patched mode: np_handler.pl sanitises input — the injected `id` is not executed,
  so no uid=/gid= output is reflected → zero findings.

Requests arrive verbatim over tcp_connect, so self.path keeps the %xx encoding
of the injection payload; the vuln branch matches on the raw path.
"""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("NETGEAR_READYNAS_MODE", "patched") == "vuln"

CMD_OUTPUT = "uid=0(root) gid=0(root) groups=0(root)\n"


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache"
    sys_version = ""

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
        path = self.path  # raw, %xx preserved
        # np_handler.pl — present in both modes. Only a vulnerable RAIDiator
        # fails to sanitise the input and executes the injected `id`.
        if path.startswith("/np_handler/np_handler.pl"):
            # Command-injection payload: backtick-wrapped `id` (%60id%60).
            if VULN_MODE and ("%60id%60" in path or "`id`" in path):
                self._send(200, "np_handler result:\n" + CMD_OUTPUT)
            else:
                # Patched: input sanitised, injection inert — benign handler
                # response with no command output reflected.
                self._send(200, "np_handler.pl: invalid request")
            return
        # FrontView handler marker — precondition only, served in BOTH modes.
        if path == "/np_handler/":
            self._send(200, "np_handler: Empty No Support")
            return
        self._send(404, "Not Found")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
