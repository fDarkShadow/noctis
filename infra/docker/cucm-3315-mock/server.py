#!/usr/bin/env python3
"""Mock Cisco Unified CM web front-end for CVE-2011-3315
(/ccmivr/IVRGetAudioFile.do 'file' parameter directory traversal)."""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs

VULN_MODE = os.environ.get("CUCM_MODE", "patched") == "vuln"

ROOT_PAGE = """<html><head><title>Cisco Unified Communications Manager</title></head>
<body><h1>Cisco Unified Communications Manager</h1>
<ul><li><a href="/ccmadmin/">Cisco Unified CM Administration</a></li>
<li><a href="/ccmservice/">Cisco Unified Serviceability</a></li>
<li><a href="/ccmuser/">Cisco Unified CM User Options</a></li></ul>
</body></html>
"""

PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "bin:x:1:1:bin:/bin:/sbin/nologin\n"
    "daemon:x:2:2:daemon:/sbin:/sbin/nologin\n"
    "nobody:x:99:99:Nobody:/:/sbin/nologin\n"
    "tomcat:x:500:500::/home/tomcat:/sbin/nologin\n"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path == "/":
            self._send(200, ROOT_PAGE, "text/html")
        elif parts.path == "/ccmivr/IVRGetAudioFile.do":
            fname = parse_qs(parts.query).get("file", [""])[0]
            if "../" in fname:
                if VULN_MODE and fname.rstrip("/").endswith("etc/passwd"):
                    self._send(200, PASSWD, "application/octet-stream")
                elif VULN_MODE:
                    self._send(404, "File not found")
                else:
                    # fixed: traversal sequences rejected
                    self._send(400, "Invalid file name")
            else:
                self._send(404, "File not found")
        else:
            self._send(404, "Not found")

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
