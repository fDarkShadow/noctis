#!/usr/bin/env python3
# Mock for Cisco ASA / Firepower WebVPN — CVE-2018-0296 directory traversal.
#
# Vuln mode: the +CSCOU+/../+CSCOE+ path confusion reaches file_list.json,
#   which reflects the traversed path (`///sessions`) and the live directory
#   listing — the genuine content a vulnerable appliance returns.
# Patched mode: the traversed path is rejected with 403 (no listing).
# Benign requests (real login portal) return the normal WebVPN page in both
#   modes and never contain the listing content — the negative control.
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("CISCO_ASA_MODE", "patched") == "vuln"

# The genuine file_list.json body a vulnerable ASA WebVPN returns for
# ?path=/sessions — it echoes the traversed path as `///sessions` and lists
# the active session files. The NOCTIS marker is incidental; the feed matches
# on the real reflected directory-listing content, not the marker.
SESSIONS_JSON = (
    '{"path":"///sessions","mtime":"","contents":['
    '{"name":"webvpn_session_0x1a2b.dat","type":"file","size":4096},'
    '{"name":"webvpn_session_0x3c4d.dat","type":"file","size":4096},'
    '{"name":".","type":"dir"},{"name":"..","type":"dir"}'
    '],"NOCTIS_CISCO_ASA_CONFIRMED":true}'
)

# Normal WebVPN clientless SSL VPN login portal.
LOGIN_PAGE = (
    "<html><head><title>SSL VPN Service</title></head>"
    "<body><h1>WebVPN Service</h1>"
    "<form action='/+webvpn+/index.html' method='post'>"
    "<input name='username'><input name='password' type='password'>"
    "</form></body></html>"
)


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

    def do_GET(self):
        path = self.path
        # The traversal probe: +CSCOU+/../+CSCOE+/files/file_list.json
        is_traversal = ("file_list.json" in path and ".." in path
                        and "CSCOU" in path and "CSCOE" in path)
        if is_traversal:
            if VULN_MODE:
                # Vulnerable: path confusion succeeds, directory is listed.
                self._send(200, SESSIONS_JSON, ct="application/json")
            else:
                # Patched: traversal rejected.
                self._send(403, "Forbidden")
            return

        # Benign WebVPN portal content (negative control).
        if path in ("/", "/+webvpn+/index.html", "/+CSCOE+/logon.html"):
            self._send(200, LOGIN_PAGE, ct="text/html")
            return

        self._send(404, "Not found")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
