#!/usr/bin/env python3
# Mock of a Siemens SIMATIC WinCC HMI "Miniweb" web server.
#
# Both modes serve /www/start.html with the "Miniweb Start Page" marker: a
# patched Miniweb instance still exposes its start page — only the directory-
# traversal flaw is fixed. The start page is therefore a gate, not the bug.
#
# vuln:    the ..%5c backslash-traversal leaks Windows system files
#          (windows/win.ini -> "[fonts]", boot.ini -> "[boot loader]").
# patched: the same traversal request is rejected (404) — no file content.
#
# The traversal payload must be matched against the RAW request path so the
# %5c backslash encoding is preserved (BaseHTTPRequestHandler does not decode
# it), exactly as the verbatim tcp_connect feed sends it.
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("WINCC_MODE", "patched") == "vuln"

START_PAGE = (
    "<html><head><title>Miniweb Start Page</title></head>"
    "<body><h1>Miniweb Start Page</h1>"
    "<p>SIMATIC WinCC - Miniweb</p></body></html>"
)

# Characteristic Windows system-file contents the traversal leaks (vuln only).
WIN_INI = (
    "; for 16-bit app support\r\n"
    "[fonts]\r\n"
    "[extensions]\r\n"
    "[mci extensions]\r\n"
    "[files]\r\n"
    "[Mail]\r\n"
    "MAPI=1\r\n"
)
BOOT_INI = (
    "[boot loader]\r\n"
    "timeout=30\r\n"
    "default=multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS\r\n"
    "[operating systems]\r\n"
    "multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS=\"Windows\" /fastdetect\r\n"
)


class Handler(BaseHTTPRequestHandler):
    # Advertise a Miniweb-like server banner.
    server_version = "Miniweb"
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
        # Raw path — %5c backslash encoding is NOT decoded here, so the
        # traversal payload arrives verbatim as the feed sent it.
        path = self.path

        # Start page: served in BOTH modes (gate only, not the vulnerability).
        if path == "/www/start.html":
            self._send(200, START_PAGE)
            return

        # Directory traversal: only the vulnerable instance leaks file content.
        if VULN_MODE and "%5c" in path.lower():
            low = path.lower()
            if low.endswith("win.ini"):
                self._send(200, WIN_INI, "text/plain")
                return
            if low.endswith("boot.ini"):
                self._send(200, BOOT_INI, "text/plain")
                return

        self._send(404, "<html><body>404 Not Found</body></html>")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
