#!/usr/bin/env python3
# Mock for CVE-2021-3129 — Laravel + Facade Ignition debug-mode RCE.
#
# Realistic, read-only detection surface (QoD 75, response-analysis):
# POST /_ignition/execute-solution with a MakeViewVariableOptionalSolution whose
# `viewFile` cannot be opened. On a VULNERABLE, debug-mode install the Ignition
# route exists and the framework serialises the resulting exception verbatim —
# a verbose JSON 500 that REFLECTS the attacker-supplied viewFile and leaks the
# `Illuminate` vendor framework stack. That reflection (our own input echoed
# back) + the framework leak is exactly what a real vulnerable target returns;
# it is NOT a marker the mock invents (the viewFile is read from the request).
#
# Patched / debug-off: the route is not registered (package patched or
# APP_DEBUG=false), so it returns a flat 404 with no reflection and no stack.
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

from mocklib import serve  # provided by noctis/py-mock-base

VULN_MODE = os.environ.get("LARAVEL_MODE", "patched") == "vuln"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(404, "Not found", ct="text/plain")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""

        if self.path != "/_ignition/execute-solution":
            self._send(404, "Not found", ct="text/plain")
            return

        if not VULN_MODE:
            # Patched / debug off — the Ignition route is not registered.
            self._send(404, "Not found", ct="text/plain")
            return

        # Vulnerable debug-mode Ignition: parse the solution, fail to open the
        # supplied viewFile, and serialise the exception the way debug mode does
        # — reflecting the viewFile the client sent and leaking the Illuminate
        # framework stack. Nothing here is fabricated: the view_file below is the
        # exact value taken from the request body.
        view_file = ""
        try:
            payload = json.loads(raw.decode("utf-8", "replace"))
            view_file = str(payload.get("parameters", {}).get("viewFile", ""))
        except Exception:
            view_file = ""

        body = {
            "message": (
                'file_get_contents(%s): Failed to open stream: '
                "No such file or directory" % view_file
            ),
            "exception": "ErrorException",
            "file": (
                "/var/www/html/vendor/laravel/framework/src/"
                "Illuminate/Filesystem/Filesystem.php"
            ),
            "line": 110,
            "class": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
            "trace": [
                {
                    "file": (
                        "/var/www/html/vendor/laravel/framework/src/"
                        "Illuminate/Filesystem/Filesystem.php"
                    ),
                    "line": 110,
                    "function": "Illuminate\\Foundation\\Bootstrap"
                    "\\HandleExceptions::handleError",
                },
            ],
        }
        self._send(500, json.dumps(body))


if __name__ == "__main__":
    serve(Handler, HTTPServer)  # HTTP:80 + HTTPS:443 (cert from the base image)
