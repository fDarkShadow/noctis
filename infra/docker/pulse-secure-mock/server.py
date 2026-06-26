#!/usr/bin/env python3
"""
Pulse Secure CVE-2019-11510 mock.
Uses Python's HTTPServer which exposes the raw path without URL normalization,
so ../  sequences in the request reach the handler intact.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("PULSE_MODE", "vuln") == "vuln"

PASSWD_CONTENT = (
    "root:x:0:0:root:/root:/bin/sh\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "pulse:x:1000:1000:Pulse Secure:/home/pulse:/bin/bash\n"
)

HOSTS_CONTENT = "127.0.0.1\tlocalhost\n::1\tlocalhost\n"

BANNER = "<html><body>Welcome to the Pulse Secure</body></html>"


class PulseHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress noise

    def send_text(self, code, body, content_type="text/plain"):
        body_bytes = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def do_GET(self):
        path = self.path  # raw, un-normalized

        # Banner endpoint — always responds (both vuln and patched)
        if "/dana-na/auth/url_default/welcome.cgi" in path:
            self.send_text(200, BANNER, "text/html")
            return

        if not VULN_MODE:
            # Patched: block any traversal attempt
            if ".." in path:
                self.send_text(404, "Not Found")
                return
            self.send_text(404, "Not Found")
            return

        # Vulnerable: path traversal is resolved server-side
        if ".." in path and "dana-na" in path:
            if "etc/passwd" in path:
                self.send_text(200, PASSWD_CONTENT)
                return
            if "etc/hosts" in path:
                self.send_text(200, HOSTS_CONTENT)
                return

        self.send_text(404, "Not Found")


def _make_https_server(handler, port):
    import ssl
    srv = HTTPServer(("0.0.0.0", port), handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/app/cert.pem", "/app/key.pem")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    import threading
    mode = "vuln" if VULN_MODE else "patched"
    http_srv = HTTPServer(("0.0.0.0", 80), PulseHandler)
    https_srv = _make_https_server(PulseHandler, 443)
    print(f"Pulse Secure mock on :80/:443 (mode={mode})", flush=True)
    threading.Thread(target=http_srv.serve_forever, daemon=True).start()
    https_srv.serve_forever()
