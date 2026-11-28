#!/usr/bin/env python3
# Inert mock for IBM WebSphere Application Server SOAP admin connector
# (CVE-2015-7450). Pure string simulation: no subprocess, no eval, no file or
# socket I/O, no real deserialization. It NEVER processes a serialized Java
# object — it only recognises a benign SOAP AdminService envelope, reflects the
# per-run nonce the feed embeds, and advertises a WAS build line.
#
#   vuln     mode → SOAP fault advertises a build in the vulnerable range
#                   (8.5.5.7 < fix 8.5.5.8) → the feed reports.
#   patched  mode → same reachable connector, but advertises a fixed build
#                   (8.5.5.8) → the feed's build-range check fails → no finding.
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("WEBSPHERE_MODE", "patched") == "vuln"

# Vulnerable mock advertises a build below the CVE-2015-7450 fix level (PI53379
# landed in 8.5.5.8); the patched mock advertises the fixed build.
WAS_BUILD = "8.5.5.7" if VULN_MODE else "8.5.5.8"

_NONCE_RE = re.compile(r"noctis[0-9a-f]{32}")

_WELCOME = (
    "<html><head><title>IBM WebSphere Application Server</title></head>"
    "<body><h1>WebSphere Application Server</h1></body></html>"
)


def _soap_fault(nonce):
    # Benign HTTP 500 SOAP fault — the normal reply a WAS SOAP connector gives
    # to an incomplete/benign urn:AdminService call. Reflects the per-run nonce
    # and advertises the build line the feed parses.
    reflected = "NOCTIS_NONCE:" + nonce if nonce else "NOCTIS_NONCE:none"
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">"
        "<SOAP-ENV:Body><SOAP-ENV:Fault>"
        "<faultcode>SOAP-ENV:Server</faultcode>"
        "<faultstring>Error reading AdminService request (incomplete envelope)</faultstring>"
        "<detail>"
        "<ns1:WASFault xmlns:ns1=\"urn:AdminService\">"
        "WAS-Build-Version: " + WAS_BUILD + " "
        + reflected + " "
        + ("NOCTIS_WEBSPHERE_CONFIRMED" if VULN_MODE else "NOCTIS_WEBSPHERE_PATCHED")
        + "</ns1:WASFault>"
        "</detail>"
        "</SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>"
    )


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Server", "WebSphere Application Server/" + WAS_BUILD)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0:
            return ""
        try:
            return self.rfile.read(length).decode("utf-8", "replace")
        except Exception:
            return ""

    def do_GET(self):
        self._send(200, _WELCOME, ct="text/html")

    def do_POST(self):
        body = self._read_body()
        soap_action = (self.headers.get("SOAPAction", "") or "").strip('"')
        m = _NONCE_RE.search(body)
        nonce = m.group(0) if m else None

        # Only the AdminService SOAP connector reflects the nonce and advertises
        # the build. A control POST without SOAPAction: urn:AdminService (or any
        # other request) gets a benign reply that reflects nothing — so blanket
        # echo cannot pass the feed's control gate.
        if "urn:AdminService" in soap_action:
            self._send(500, _soap_fault(nonce), ct="text/xml; charset=utf-8")
        else:
            self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
