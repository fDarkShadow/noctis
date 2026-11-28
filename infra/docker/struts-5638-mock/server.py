#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("STRUTS_MODE", "patched") == "vuln"

# Signature of the S2-045 OGNL payload carried in the Content-Type header.
OGNL_MARKERS = ("%{", "com.opensymphony.xwork2.ActionContext.container")

# Emulated /etc/passwd leaked by the injected `cat /etc/passwd` command,
# plus a noctis marker proving this mock produced the output.
PASSWD = (
    "NOCTIS_STRUTS_RCE_CONFIRMED\n"
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
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

    def _ognl_in_content_type(self):
        ct = self.headers.get("Content-Type", "") or ""
        return all(m in ct for m in OGNL_MARKERS)

    def do_GET(self):
        if VULN_MODE and self._ognl_in_content_type():
            # Jakarta Multipart parser evaluates the Content-Type OGNL and
            # returns the command output.
            self._send(200, PASSWD)
        else:
            # Patched Struts (or a benign request) ignores the Content-Type
            # OGNL and serves a normal page.
            self._send(200, "<html><body>Struts welcome</body></html>", "text/html")

    def do_POST(self):
        self.do_GET()


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
