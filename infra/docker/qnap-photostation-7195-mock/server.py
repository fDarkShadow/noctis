#!/usr/bin/env python3
# Mock for QNAP Photo Station path traversal / arbitrary file read (CVE-2019-7195).
#
# Path-sensitivity is the whole point of this mock: the caption/subtitle download
# endpoint discloses the (inert, fabricated) sentinel ONLY when the `f` parameter
# carries a real traversal payload. An identical request without a traversal
# payload returns 404, so a scanner cannot confirm the bug from a constant marker
# — it has to prove the traversal differential.
#
# Vuln  : /photo/p/api/video.php?a=caption&f=<traversal>  -> 200 + attachment
#         any non-traversal `f`                            -> 404
# Patched: the same endpoint rejects every caption request -> 403 (fix applied)
#
# The disclosed body is an inert fabricated account line, never a real secret.
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("QNAP_PHOTOSTATION_MODE", "patched") == "vuln"

# Inert, fabricated sentinel — NOT a real system file.
SENTINEL = (
    "admin:x:0:0:Administrator:/share/homes/admin:/bin/sh\n"
    "httpdusr:x:99:99:NOCTIS_QNAP_CONFIRMED:/:/sbin/nologin\n"
)

LOGIN_PAGE = (
    "<html><head><title>QNAP Photo Station</title></head>"
    "<body><h1>Photo Station</h1><div id='login'></div></body></html>"
)


def _has_traversal(path):
    low = path.lower()
    return ("%2e" in low) or (".." in path) or ("%252e" in low)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/plain", extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def do_GET(self):
        raw = self.path
        path = raw.split("?")[0]
        query = raw[len(path) + 1:] if "?" in raw else ""

        if path == "/" or path == "/photo/" or path == "/photo/index.php":
            self._send(200, LOGIN_PAGE, "text/html")
            return

        if path == "/photo/p/api/video.php" and "a=caption" in query:
            if not VULN_MODE:
                # Patched: traversal is sanitised, caption download rejected.
                self._send(403, '{"status":0,"msg":"forbidden"}', "application/json")
                return
            if _has_traversal(query):
                # Vulnerable: the unsanitised `f` discloses the file as an attachment.
                self._send(
                    200,
                    SENTINEL,
                    "video/subtitle",
                    {"Content-Disposition": 'attachment; filename="passwd.srt"'},
                )
                return
            # Vulnerable server, but a benign (non-traversal) caption request
            # resolves no real subtitle -> not found. (Enforces path-sensitivity.)
            self._send(404, '{"status":0,"msg":"not found"}', "application/json")
            return

        self._send(404, "Not found")

    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/photo/p/api/album.php":
            body = self._read_body().decode("latin-1", "replace")
            if "a=setSlideshow" in body:
                # Legitimate slideshow-context API: present in both modes.
                self._send(200, '{"status":1}', "application/json")
                return
            self._send(200, '{"status":0}', "application/json")
            return
        self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
