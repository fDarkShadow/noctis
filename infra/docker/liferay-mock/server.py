#!/usr/bin/env python3
# Inert mock for CVE-2020-7961 (Liferay Portal unauthenticated JSONWS RCE).
#
# Detection is EXPOSURE-based and inert: the feed probes the unauthenticated
# JSONWS invoker (/api/jsonws/<marker>) with a benign, per-run random marker and
# checks that a vulnerable (exposed) instance reflects that exact marker in its
# JSON error body, while a control path does NOT. NO deserialization gadget is
# ever sent, and this mock performs ONLY string operations: no eval/exec, no
# subprocess, no file I/O, no outbound sockets, no real deserialization.
#
# LIFERAY_MODE selects behaviour (default "patched"):
#   vuln           - JSONWS invoker exposed: /api/jsonws/* -> 200, echoes the
#                    requested service-path segment (the per-run marker); every
#                    other path -> 404 with no echo.
#   patched        - JSONWS invoker locked down: everything -> 404, no echo.
#   cheat_404      - JSONWS endpoint returns 404 (endpoint-404 reviewer cheat).
#   cheat_constant - JSONWS echoes a FIXED marker, never the per-run one
#                    (constant-marker reviewer cheat).
#   cheat_reflect  - EVERY path reflects its last segment, including the control
#                    path (reflect-everywhere reviewer cheat).
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
from mocklib import serve

MODE = os.environ.get("LIFERAY_MODE", "patched")

JSONWS_PREFIX = "/api/jsonws/"
# Static product marker (underscore => never matches the feed's NOCTIS[0-9a-f]{32}).
CONFIRMED = "NOCTIS_LIFERAY_CONFIRMED"
# Fixed decoy used only by the constant-marker cheat mode.
CONSTANT_SEG = "NOCTIS" + ("a" * 32)


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

    def _jsonws_body(self, seg):
        # Mimics Liferay's JSONWS invoker error, which reflects the requested
        # (invalid) service path back to the caller.
        return (
            '{"exception":"No JSON web service action associated with path /'
            + seg
            + '","marker":"'
            + CONFIRMED
            + '"}'
        )

    def _route(self):
        path = urlparse(self.path).path

        if MODE == "cheat_reflect":
            # Reflect the last path segment on EVERY path, control included.
            seg = path.rstrip("/").split("/")[-1]
            self._send(200, self._jsonws_body(seg))
            return

        if path.startswith(JSONWS_PREFIX):
            seg = path[len(JSONWS_PREFIX):]
            if MODE == "vuln":
                self._send(200, self._jsonws_body(seg))
                return
            if MODE == "cheat_constant":
                self._send(200, self._jsonws_body(CONSTANT_SEG))
                return
            # patched / cheat_404: JSONWS invoker is not reachable.
            self._send(404, '{"error":"not found"}')
            return

        # Non-JSONWS paths (control request) never echo.
        self._send(404, '{"error":"not found"}')

    def do_GET(self):
        self._route()

    def do_POST(self):
        self._route()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
