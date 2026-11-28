#!/usr/bin/env python3
"""Mock for Microsoft HTTP.sys MS15-034 / CVE-2015-1635.

The real bug is an integer overflow in HTTP.sys range arithmetic: an oversized
upper bound in a Range header makes an unpatched stack answer 416 "The requested
range is not satisfiable" from a Microsoft/IIS server, while a normal request
answers 200.

Vuln mode   : oversized Range -> 416 overflow signature (Microsoft banner);
              any other request (incl. a sane Range) -> 200.
Patched mode: every request -> 200; the oversized Range is clamped/handled, so
              the 416 overflow signature never appears.

The probe is inert: a single oversized-Range GET that only reads this static
page. No crash, no DoS loop, no file writes.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("HTTPSYS_MODE", "patched") == "vuln"

# HTTP.sys overflows when the range upper bound is absurdly large. A legitimate
# Range (e.g. bytes=0-1023) is well below this; the MS15-034 probe uses 2^64-1.
OVERFLOW_THRESHOLD = 2 ** 32

OK_BODY = (
    "<html><head><title>IIS</title></head><body>\r\n"
    "NOCTIS_HTTPSYS_CONFIRMED\r\n"
    "</body></html>"
)
# The exact IIS 416 error page text the matcher keys on.
RANGE_416_BODY = (
    "<html><head><title>416 - Requested Range Not Satisfiable</title></head>\r\n"
    "<body><h2>416 - The requested range is not satisfiable.</h2>\r\n"
    "NOCTIS_HTTPSYS_CONFIRMED\r\n"
    "</body></html>"
)


def _oversized_range(range_header):
    """True iff the Range header carries an overflow-sized upper bound."""
    if not range_header or "=" not in range_header:
        return False
    try:
        spec = range_header.split("=", 1)[1]           # "0-18446744073709551615"
        first = spec.split(",")[0]                       # first range
        hi = first.split("-", 1)[1].strip()              # upper bound
        if not hi:
            return False
        return int(hi) >= OVERFLOW_THRESHOLD
    except (ValueError, IndexError):
        return False


class Handler(BaseHTTPRequestHandler):
    # The Microsoft/IIS server banner the matcher keys on (emitted as the
    # single "Server:" header by send_response via version_string()).
    server_version = "Microsoft-IIS/8.5"
    sys_version = ""

    def log_message(self, *args):
        pass

    def version_string(self):
        return self.server_version

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        range_header = self.headers.get("Range")
        if VULN_MODE and _oversized_range(range_header):
            # Unpatched HTTP.sys: the overflow surfaces as a 416 error page.
            self._send(416, RANGE_416_BODY)
        else:
            # Patched host, or any non-overflow request: normal 200.
            self._send(200, OK_BODY)

    def do_POST(self):
        self.do_GET()

    def do_HEAD(self):
        self._send(200, "")


if __name__ == "__main__":
    serve(Handler, HTTPServer)   # HTTP:80 + HTTPS:443 (cert from the base image)
