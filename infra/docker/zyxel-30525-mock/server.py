#!/usr/bin/env python3
# Mock Zyxel firewall ZTP CGI for CVE-2022-30525.
#
# Vuln mode: /ztp/cgi-bin/handler is reachable WITHOUT authentication and the
#   ZTP CGI processes a setWanPortSt command, answering with the handler's own
#   JSON output (HTTP 200, module "ztp"). This mirrors the real vulnerable
#   condition: the handler is reachable pre-auth and processes the command.
# Patched mode: the ZTP path is restricted; unauthenticated requests are
#   rejected (403) so the handler is never reached and detection fails.
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("ZYXEL_MODE", "patched") == "vuln"


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

    def do_POST(self):
        if self.path == "/ztp/cgi-bin/handler":
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            try:
                cmd = json.loads(raw).get("command", "")
            except Exception:
                cmd = ""

            if not VULN_MODE:
                # Patched: ZTP handler requires authentication / is restricted.
                self._send(403, "Access denied")
                return

            if cmd == "setWanPortSt":
                # Vulnerable: the unauthenticated ZTP CGI handler processed the
                # WAN-port command and returns its own handler response.
                body = json.dumps({
                    "result": "ok",
                    "module": "ztp",
                    "handler": "wan_port",
                    "stage": "provision",
                    "applied": False,
                })
                self._send(200, body, ct="application/json")
            else:
                self._send(200, json.dumps({"result": "error",
                                            "module": "ztp"}),
                           ct="application/json")
        else:
            self._send(404, "Not found")

    def do_GET(self):
        self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
