#!/usr/bin/env python3
"""Mock Fortinet FortiOS admin REST API for CVE-2022-40684 (auth bypass).

The vulnerable branch mirrors FortiOS behaviour: the admin REST API is reachable
WITHOUT authentication only when the request carries the crafted trusted-origin
signals the real bypass relies on — the internal "Report Runner" User-Agent and a
"Forwarded:" header spoofing a loopback source/destination. A request to the same
path WITHOUT those signals is rejected (401), so the detection keys on the genuine
bypass rather than a constant marker. The patched branch rejects (401) regardless.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

from mocklib import serve   # provided by noctis/py-mock-base

VULN_MODE = os.environ.get("FORTIOS_40684_MODE", "patched") == "vuln"

ADMIN_PATH = "/api/v2/cmdb/system/admin"

# The authenticated admin-object JSON a real FortiOS returns for GET of the admin
# cmdb table: a "success" envelope whose results array holds the admin account.
ADMIN_JSON = (
    '{"http_method":"GET","size":1,"matched_count":1,"next_idx":1,'
    '"revision":"a1b2c3d4e5f60718293a4b5c6d7e8f90",'
    '"results":[{"name":"admin","q_origin_key":"admin","wildcard":"disable",'
    '"remote-auth":"disable","accprofile":"super_admin","vdom":[{"name":"root",'
    '"q_origin_key":"root"}],"ssh-public-key1":"","ssh-public-key2":"",'
    '"trusthost1":"0.0.0.0 0.0.0.0","two-factor":"disable","force-password-change":'
    '"disable"}],"vdom":"root","path":"system","name":"admin","status":"success",'
    '"http_status":200,"serial":"FGVMEVZQ4N8PK3LT","version":"v7.2.1","build":1255}'
)


def _has_bypass_signals(headers):
    ua = (headers.get("User-Agent") or "")
    fwd = (headers.get("Forwarded") or "")
    # The real bypass needs the internal component User-Agent AND a Forwarded
    # header asserting a trusted (loopback) origin.
    return "Report Runner" in ua and "for=" in fwd and "by=" in fwd


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

    def _reject(self):
        body = b'{"http_status":401,"status":"error","error":-1}'
        self.send_response(401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == ADMIN_PATH:
            if VULN_MODE and _has_bypass_signals(self.headers):
                self._send(200, ADMIN_JSON)
            else:
                # Patched devices, and vulnerable devices without the crafted
                # trusted-origin request, reject the unauthenticated call.
                self._reject()
        else:
            self._send(404, b'{"http_status":404,"status":"error"}')

    def do_POST(self):
        self.do_GET()

    def do_PUT(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)   # HTTP:80 + HTTPS:443 (cert from the base image)
