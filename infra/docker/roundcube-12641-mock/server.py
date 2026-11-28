#!/usr/bin/env python3
# Mock for CVE-2020-12641 — Roundcube Webmail installer command injection via
# the ImageMagick path options (im_convert_path / im_identify_path).
#
# Vuln mode: the installer (installer/index.php) is still reachable. Its config
# test step (_step=3) echoes the submitted ImageMagick path fields back into the
# page — exactly the behaviour that lets an attacker plant a shell command. The
# mock REFLECTS whatever value the request sent in `_im_convert_path`; it does
# NOT fabricate a fixed marker. With no `_im_convert_path` field in the body it
# serves the plain installer page (no reflection) — so a benign probe that lacks
# the trigger field yields no detection (negative control).
#
# Patched mode: the installer is removed/disabled; installer/index.php returns
# 404, so the path fields are never echoed and detection fails.
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("ROUNDCUBE_MODE", "patched") == "vuln"

INSTALLER_PATHS = ("/installer/index.php", "/roundcube/installer/index.php")

INSTALLER_FORM = (
    "<html><head><title>Roundcube Webmail Installer</title></head><body>"
    "<h1>Roundcube Webmail Installer</h1>"
    "<form method=post><input name=_im_convert_path>"
    "<input name=_im_identify_path></form></body></html>"
)


class Handler(BaseHTTPRequestHandler):
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

    def _handle_installer(self):
        if not VULN_MODE:
            # Patched: installer removed after setup.
            self._send(404, "Not Found", "text/plain")
            return

        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        params = urllib.parse.parse_qs(raw, keep_blank_values=True)
        convert = params.get("_im_convert_path", [""])[0]
        identify = params.get("_im_identify_path", [""])[0]

        # Only the config-test step echoes the path fields. Reflect ONLY what the
        # request supplied — no field, no reflection.
        if convert or identify:
            body = (
                "<html><head><title>Roundcube Webmail Installer</title></head><body>"
                "<h1>Roundcube Webmail Installer</h1>"
                "<h2>Check config</h2>"
                "<p>Testing config file...</p>"
                "<div class='imagemagick'>"
                "<p>im_convert_path: <code>{}</code></p>"
                "<p>im_identify_path: <code>{}</code></p>"
                "</div></body></html>"
            ).format(convert, identify)
            self._send(200, body)
        else:
            self._send(200, INSTALLER_FORM)

    def do_GET(self):
        if self.path.split("?", 1)[0] in INSTALLER_PATHS:
            if not VULN_MODE:
                self._send(404, "Not Found", "text/plain")
            else:
                self._send(200, INSTALLER_FORM)
            return
        if self.path == "/" or self.path.startswith("/?_task=login"):
            self._send(200, "<html><body>Welcome to Roundcube Webmail</body></html>")
        else:
            self._send(404, "Not Found", "text/plain")

    def do_POST(self):
        if self.path.split("?", 1)[0] in INSTALLER_PATHS:
            self._handle_installer()
        else:
            self._send(404, "Not Found", "text/plain")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
