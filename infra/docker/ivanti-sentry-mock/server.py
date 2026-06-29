#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, unquote_plus

VULN_MODE = os.environ.get("IVANTI_SENTRY_MODE", "patched") == "vuln"

MICS_ENDPOINT = "/mics/api/v2/sentry/mics-config/handleMessage"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""

    def do_GET(self):
        self._send(200, b"<html><title>Ivanti Sentry</title></html>", "text/html")

    def do_POST(self):
        if self.path != MICS_ENDPOINT:
            self._send(404, b"Not found", "text/plain")
            return

        if not VULN_MODE:
            self._send(403, b"Forbidden", "text/plain")
            return

        body = self._read_body()
        # Parse the URL-encoded form body to extract the message parameter
        params = parse_qs(body)
        message = params.get("message", [""])[0]

        # Check for commandexec payload with reqandres element
        if "commandexec" in message and "reqandres" in message:
            # Extract the <reqandres> content (the OS command)
            import re
            m = re.search(r"<reqandres>(.*?)</reqandres>", message)
            if m:
                cmd = m.group(1).strip()
                # Simulate echo command output
                if cmd.startswith("echo "):
                    echo_output = cmd[5:]
                    self._send(200, f"Message handled successfully\n{echo_output}\n")
                    return

        self._send(200, b"Message handled successfully\n")

    def do_PUT(self): self.do_POST()

def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/certs/server.crt", "/certs/server.key")
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv

if __name__ == "__main__":
    https = _make_https_server(443)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
