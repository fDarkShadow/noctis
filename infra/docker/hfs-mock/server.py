#!/usr/bin/env python3
import os, re, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote

VULN_MODE = os.environ.get("HFS_MODE", "patched") == "vuln"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        raw_path = self.path
        decoded_path = unquote(raw_path)

        # CVE-2014-6287: HFS < 2.3c null-byte search macro injection. A
        # {.cookie|name|value.} macro in the search parameter (prefixed with a
        # %00 null byte) is evaluated server-side, reflecting the value as a
        # Set-Cookie header. Matched before the CVE-2024-23692 cmd=/exec branch.
        m = re.search(r"\{\.cookie\|([^|]+)\|([^.]+)\.\}", decoded_path)
        is_cookie_injection = (
            "search=" in raw_path and "%00" in raw_path and m is not None
        )
        if VULN_MODE and is_cookie_injection:
            name, value = m.group(1), m.group(2)
            body = b"<html><title>HFS /</title></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", f"{name}={value};")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        is_injection = "cmd=" in decoded_path and (
            "exec" in decoded_path or "{." in decoded_path
        )

        if VULN_MODE and is_injection:
            parsed = urlparse(decoded_path)
            params = parse_qs(parsed.query)
            cmd = params.get("cmd", [""])[0]
            body = f"<html><body>RESULT:\n{cmd}\n====</body></html>"
            self._send(200, body)
        else:
            self._send(200, "<html><title>HFS - HTTP File Server</title></html>")

    def do_POST(self): self.do_GET()

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
