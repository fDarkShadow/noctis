#!/usr/bin/env python3
# Mock for CVE-2013-1965 (Apache Struts2 S2-012 showcase app exposure).
# Ported detection target of OpenVAS NASL 2012/apache/gb_struts_s2-012_active.nasl
# Vuln mode: POST /showcase.action returns the Struts Showcase landing page
#            (body matches ">Showcase</" and ">Struts Showcase<").
# Patched mode: /showcase.action returns 404 so no finding fires.
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("STRUTS_1965_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

SHOWCASE_BODY = (
    "<!DOCTYPE html>\n<html><head><title>Struts2 Showcase</title></head>\n"
    "<body><h1>Struts Showcase</h1>\n"
    "<a href=\"index.action\">Showcase</a>\n"
    "</body></html>\n"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self._read_body()
        if self.path == "/showcase.action":
            if VULN_MODE:
                self._send(200, SHOWCASE_BODY)
            else:
                self._send(404, "Not found")
        else:
            self._send(404, "Not found")

    def do_GET(self):
        self._send(404, "Not found")


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(CERT_DIR, "server.crt"), os.path.join(CERT_DIR, "server.key"))
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    if PORT_HTTPS:
        threading.Thread(target=lambda: _make_https_server(PORT_HTTPS).serve_forever(), daemon=True).start()
    if PORT_HTTP:
        HTTPServer(("0.0.0.0", PORT_HTTP), Handler).serve_forever()
    else:
        threading.Event().wait()
