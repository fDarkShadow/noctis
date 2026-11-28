#!/usr/bin/env python3
# Mock for CVE-2022-24112 — Apache APISIX batch-requests Admin API bypass.
#
# vuln mode:    the batch-requests endpoint honours a caller-supplied
#               X-Real-IP: 127.0.0.1, so the pipelined Admin API sub-request
#               bypasses the IP restriction and returns the route listing.
#               WITHOUT the spoofed loopback IP the sub-request is rejected
#               (401) — the bypass is gated on the spoof header.
# patched mode: the spoofed IP is ignored; the Admin API sub-request is always
#               rejected (401), regardless of the X-Real-IP header.
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("APISIX_MODE", "patched") == "vuln"

# Genuine Admin API route listing (etcd-style node), as the real /apisix/admin/routes
# returns it. json.dumps does not escape '/', so "/apisix/routes/1" survives verbatim.
ADMIN_ROUTES = json.dumps({
    "total": 1,
    "list": [{
        "key": "/apisix/routes/1",
        "value": {"id": "1", "uri": "/get", "status": 1,
                  "upstream": {"type": "roundrobin", "nodes": {"127.0.0.1:80": 1}}},
        "modifiedIndex": 12,
        "createdIndex": 12,
    }],
})
ADMIN_UNAUTH = json.dumps({"error_msg": "failed to check token"})


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
        if self.path != "/apisix/batch-requests":
            self._send(404, "Not found")
            return

        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw)
        except ValueError:
            self._send(400, "Bad Request")
            return

        # The spoofed loopback IP can be supplied either on the outer HTTP
        # request or inside the batch "headers" block (real APISIX merges both
        # into the sub-request client IP).
        spoofed = self.headers.get("X-Real-IP", "")
        batch_headers = payload.get("headers") or {}
        if not spoofed:
            spoofed = batch_headers.get("X-Real-IP", "") or batch_headers.get("x-real-ip", "")
        bypass = VULN_MODE and spoofed.strip() == "127.0.0.1"

        sub = []
        for req in (payload.get("pipeline") or []):
            path = req.get("path", "")
            if path.startswith("/apisix/admin/"):
                if bypass:
                    sub.append({"status": 200, "reason": "OK", "body": ADMIN_ROUTES,
                                "headers": {"Content-Type": "application/json"}})
                else:
                    sub.append({"status": 401, "reason": "Unauthorized", "body": ADMIN_UNAUTH,
                                "headers": {"Content-Type": "application/json"}})
            else:
                sub.append({"status": 404, "reason": "Not Found", "body": "{}",
                            "headers": {"Content-Type": "application/json"}})

        self._send(200, json.dumps(sub), ct="application/json")

    def do_GET(self):
        # The Admin API itself: always rejects direct (non-loopback) access.
        if self.path.startswith("/apisix/admin/"):
            self._send(401, ADMIN_UNAUTH, ct="application/json")
        else:
            self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
