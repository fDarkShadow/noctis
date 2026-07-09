#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

VULN_MODE = os.environ.get("VIGORCONNECT_MODE", "patched") == "vuln"

FP_BODY = b"<html><title>DrayTek VigorConnect</title><body>VigorConnect</body></html>"

PASSWD_BODY = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
).encode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html", extra_headers=None):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/":
            self._send(200, FP_BODY)
            return

        if path == "/ACSServer/DownloadFileServlet":
            qs = parse_qs(parsed.query)
            show_file = qs.get("show_file_name", [""])[0]

            if not VULN_MODE:
                self._send(403, b"Access denied")
                return

            if "passwd" in show_file or "etc" in show_file:
                self._send(200, PASSWD_BODY, "application/octet-stream",
                           {"Content-Disposition": "attachment; filename=passwd"})
            else:
                self._send(200, b"", "application/octet-stream")
            return

        self._send(404, b"Not found")


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
