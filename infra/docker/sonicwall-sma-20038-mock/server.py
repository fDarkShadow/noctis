#!/usr/bin/env python3
# Inert mock for SonicWall SMA100 CVE-2021-20038 (pre-auth httpd/CGI stack
# buffer overflow). PURE STRING SIMULATION — no subprocess, exec, file I/O or
# raw sockets. It never processes an overflow payload; it only advertises a
# firmware version and exposes the management CGI path so the feed's safe
# differential (fingerprint + reachable CGI + version compare) can fire.
#
#   vuln mode    → firmware 10.2.1.2-24sv (affected build; fixed at 10.2.1.3-27sv)
#   patched mode → firmware 10.2.1.4-29sv (fixed build) — version gate fails
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("SONICWALL_SMA100_MODE", "patched") == "vuln"

FW_VERSION = "10.2.1.2-24sv" if VULN_MODE else "10.2.1.4-29sv"

WELCOME_BODY = (
    "<html><head><title>SonicWall - Virtual Office</title></head>\n"
    "<body>\n"
    "<h1>SMA 100 Series</h1>\n"
    "<!-- NOCTIS_SONICWALL_SMA100_CONFIRMED -->\n"
    "<div id='product'>SonicWall SMA 100 Series</div>\n"
    "<div id='firmware'>Firmware Version: {ver}</div>\n"
    "</body></html>\n"
)

MANAGEMENT_BODY = "Authentication required\n"


class Handler(BaseHTTPRequestHandler):
    # Default Server header becomes the SMA100 management httpd banner.
    server_version = "SonicWALL SSL-VPN Web Server"
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
        if self.path == "/cgi-bin/welcome":
            self._send(200, WELCOME_BODY.format(ver=FW_VERSION))
        elif self.path == "/cgi-bin/management":
            # The vulnerable httpd/CGI handler is present in both builds; the
            # firmware version is the differential the feed keys on.
            self._send(200, MANAGEMENT_BODY, "text/plain")
        else:
            self._send(404, "Not Found", "text/plain")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
