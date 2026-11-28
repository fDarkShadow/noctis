#!/usr/bin/env python3
# Inert mock for CVE-2021-40539 (Zoho ManageEngine ADSelfService Plus REST API
# auth bypass). PURE STRING SIMULATION — no subprocess, no os.system, no exec,
# no file write, no upload. The vuln mode models a security filter that FAILS
# OPEN on a "/./" path prefix: the privileged RestAPI action runs without auth
# and benignly echoes back whatever per-run nonce the caller submitted. The
# patched mode enforces auth on the normalised RestAPI path and returns 403,
# never reflecting the nonce.
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("ADSSP_MODE", "patched") == "vuln"

# RestAPI servlet actions that the auth filter is supposed to protect.
PROTECTED = "/RestAPI/LogonCustomization"
NONCE_RE = re.compile(rb"NOCTIS[0-9a-f]{32}")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "ADSelfService Plus")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > 0:
            return self.rfile.read(length)
        return b""

    def do_GET(self):
        if self.path.rstrip("/").endswith("/RestAPI/LogonCustomization") or \
           self.path.startswith("/webclient"):
            self._send(200, "<html><body>ManageEngine ADSelfService Plus</body></html>")
        else:
            self._send(404, "Not found")

    def do_POST(self):
        body = self._read_body()
        # Auth filter fails open ONLY when the "/./" bypass prefix is present;
        # a normalised path is still guarded. Both normalise to PROTECTED.
        bypass = self.path.startswith("/./") and PROTECTED in self.path
        guarded = self.path.endswith(PROTECTED) and not self.path.startswith("/./")
        authed = self.headers.get("Authorization") is not None

        if guarded and not authed:
            # Direct, non-bypassed access to the protected action → auth required.
            self._send(401, "Authorization required", "text/plain")
            return

        if bypass and VULN_MODE:
            # Filter failed open → privileged action runs unauthenticated and
            # benignly reflects the submitted nonce. Marker aids manual triage.
            m = NONCE_RE.search(body)
            nonce = m.group(0).decode() if m else "none"
            page = (
                "<html><head><title>LogonCustomization</title></head><body>"
                "NOCTIS_ADSSP_CONFIRMED saved=true form=smartcard "
                f"customization-token={nonce}"
                "</body></html>"
            )
            self._send(200, page)
            return

        if bypass and not VULN_MODE:
            # Patched: the "/./" trick no longer escapes the auth filter.
            self._send(403, "Forbidden", "text/plain")
            return

        self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
