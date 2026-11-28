#!/usr/bin/env python3
"""Mock for Atlassian Crowd pdkinstall unauthenticated RCE (CVE-2019-11580).

Pure string handling only: the mock parses the uploaded multipart body, echoes
the nonce it carried, and returns a canned response. It NEVER executes a plugin,
writes to a webroot, or spawns a subprocess.

Modes (CROWD_MODE):
  vuln       pdkinstall enabled: 200 + marker + reflected per-run nonce
  patched    pdkinstall disabled: 404, benign body, no marker/nonce
  constant   accepts (200 + marker) but does NOT reflect the per-run nonce
  negcontrol reflects the nonce but still requires auth (401)
"""
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

MODE = os.environ.get("CROWD_MODE", "patched")

PDK_PATHS = ("/crowd/admin/uploadplugin.action", "/crowd/rest/plugins/1.0/")


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

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0:
            return ""
        return self.rfile.read(length).decode("utf-8", errors="replace")

    def _extract_token(self, body):
        m = re.search(r'filename="noctis-([0-9a-fA-F]+)\.jar"', body)
        return m.group(1) if m else ""

    def do_GET(self):
        # A plain landing page so a bare TCP/HTTP GET succeeds in both modes.
        self._send(200, "<html><title>Crowd</title>Atlassian Crowd</html>")

    def do_POST(self):
        if not any(self.path.startswith(p) for p in PDK_PATHS):
            self._send(404, "<html>Not found</html>")
            return

        body = self._read_body()
        tok = self._extract_token(body)

        if MODE == "vuln":
            # pdkinstall enabled -> unauthenticated install accepted, nonce echoed.
            self._send(
                200,
                "<html><head><title>Install plugin</title></head><body>"
                "pdkinstall development plugin is enabled; plugin install accepted "
                "(CVE-2019-11580). NOCTIS_CROWD_CONFIRMED "
                "installed-plugin=noctis-{}.jar</body></html>".format(tok),
            )
        elif MODE == "constant":
            # Accepts, but returns a static body with no per-run nonce.
            self._send(
                200,
                "<html><body>pdkinstall accepted. NOCTIS_CROWD_CONFIRMED "
                "installed-plugin=noctis-static.jar</body></html>",
            )
        elif MODE == "negcontrol":
            # Echoes the nonce but still enforces auth (non-200).
            self._send(
                401,
                "<html><body>Unauthorized. NOCTIS_CROWD_CONFIRMED "
                "received-token=noctis-{}.jar</body></html>".format(tok),
            )
        else:
            # patched -> pdkinstall disabled, request rejected, no marker.
            self._send(404, "<html><body>Plugin management endpoint not available.</body></html>")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
