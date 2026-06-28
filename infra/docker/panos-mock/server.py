#!/usr/bin/env python3
"""Mock Palo Alto PAN-OS GlobalProtect server — CVE-2024-3400 (SESSID path traversal)."""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("PANOS_MODE", "patched") == "vuln"

# Module-level store shared between HTTP and HTTPS handlers.
# Maps probe filename → True (file was "written" via SESSID traversal).
_written_files: dict = {}
_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body=b"", ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _extract_probe_filename(self):
        """Extract filename from SESSID cookie path traversal."""
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("SESSID="):
                sessid = part[len("SESSID="):]
                # SESSID contains a traversal path ending in the probe filename
                filename = sessid.rstrip("/").rsplit("/", 1)[-1]
                if filename:
                    return filename
        return None

    def do_GET(self):
        if self.path.startswith("/global-protect/portal/images/"):
            filename = self.path.split("/")[-1]
            with _lock:
                exists = _written_files.get(filename, False)
            if exists:
                # File was written — portal serves it as 403 (access denied)
                self._send(403, b"<html>Forbidden</html>")
            else:
                self._send(404, b"<html>Not Found</html>")
        else:
            self._send(404, b"<html>Not Found</html>")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        _body = self.rfile.read(length)

        if self.path == "/ssl-vpn/hipreport.esp":
            if VULN_MODE:
                filename = self._extract_probe_filename()
                if filename:
                    with _lock:
                        _written_files[filename] = True
                self._send(200, b"invalid required input parameters", ct="text/html")
            else:
                # Patched: reject the traversal attempt
                self._send(400, b"<html>Bad Request</html>")
        else:
            self._send(404, b"<html>Not Found</html>")


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/app/cert.pem", "/app/key.pem")
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    mode = "vuln" if VULN_MODE else "patched"
    https = _make_https_server(443)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    print(f"PAN-OS mock on :80/:443 (mode={mode})", flush=True)
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
