#!/usr/bin/env python3
"""Inert mock for CVE-2021-35587 (Oracle Access Manager OpenSSO Agent exposure).

Pure string simulation — no subprocess/exec/eval/file I/O/sockets/real
deserialization. The vulnerable mode reproduces the observable exposure the inert
feed keys on: the unauthenticated OpenSSO/OAM endpoint fails open and REFLECTS the
per-run nonce carried in the request, while normal paths do not. It never performs
or simulates Java deserialization.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from mocklib import serve

MODE = os.environ.get("ORACLE_OAM_MODE", "patched")
VULN_MODE = MODE == "vuln"

# Static product marker (issue convention). The feed does NOT key on this; it keys
# on reflection of the per-run nonce. It is here only for realism / fingerprinting.
STATIC_MARKER = "NOCTIS_ORACLE_OAM_CONFIRMED"

_CSS = "/* OAM login page */\n.oam-login { color: #000; }\n"

# Oracle Access Manager response headers seen on real OAM deployments.
_OAM_HEADERS = {
    "x-oracle-dms-ecid": "005xNOCTISdmsEcid0000000000",
    "x-oracle-dms-rid": "0:1",
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _nonce(self):
        """The 'noctis' query parameter, if present (benign reflected marker)."""
        qs = parse_qs(urlparse(self.path).query)
        vals = qs.get("noctis")
        return vals[0] if vals else ""

    def do_GET(self):
        path = urlparse(self.path).path
        is_opensso = path.startswith("/oam/server/opensso")
        is_control = path == "/oam/pages/css/general.css"

        if is_opensso:
            self._opensso()
        elif is_control:
            self._control()
        else:
            self._send(404, "<html><body>404 Not Found</body></html>")

    def _opensso(self):
        nonce = self._nonce()
        if MODE == "endpoint_404":
            # Cheating mock: endpoint not reachable.
            self._send(404, "<html><body>404 Not Found</body></html>")
            return
        if MODE == "constant_marker":
            # Cheating mock: returns a FIXED marker, not the per-run nonce.
            body = (
                "<html><body>OpenSSO agent error "
                "NOCTIS0123456789abcdef0123456789abcdef "
                f"{STATIC_MARKER}</body></html>"
            )
            self._send(200, body, extra=_OAM_HEADERS)
            return
        if MODE in ("vuln", "reflect_all"):
            # Fails open: reflects the per-run nonce in the error response.
            body = (
                "<html><head><link href=\"/oam/pages/css/general.css\"/></head>"
                f"<body>OpenSSO agent error for request {nonce} "
                f"{STATIC_MARKER}</body></html>"
            )
            self._send(200, body, extra=_OAM_HEADERS)
            return
        # patched: locked down.
        self._send(403, "<html><body>403 Forbidden</body></html>")

    def _control(self):
        nonce = self._nonce()
        if MODE == "reflect_all":
            # Cheating mock: reflects the nonce everywhere, including the control path.
            self._send(200, f"{_CSS}/* {nonce} */\n", ct="text/css", extra=_OAM_HEADERS)
            return
        # Sound target (vuln or patched): CSS served, nonce NOT reflected.
        self._send(200, _CSS, ct="text/css", extra=_OAM_HEADERS)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
