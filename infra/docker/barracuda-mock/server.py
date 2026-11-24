#!/usr/bin/env python3
"""Mock Barracuda Networks appliance — CVE-2010-20109 directory traversal.

The appliance web UI identifies itself with a ``Server: BarracudaHTTP``
header (both modes). In vuln mode, view_help.cgi fails to sanitise the
``locale`` parameter: a ``../`` + NUL-byte payload escapes the CGI directory
and leaks the appliance config snapshot (containing ``system_password``,
``system_netmask``, ``system_default_domain``). In patched mode the same
request is rejected (404) and no snapshot content is leaked.

The raw request path is matched against ``self.path`` so the verbatim
``%00``/``../`` payload sent by the feed's tcp_connect step is preserved.
"""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("BARRACUDA_MODE", "patched") == "vuln"

# Leaked appliance config snapshot — the fields the NASL pattern/extra_check
# look for (system_password / system_netmask / system_default_domain).
# Field order intentionally lists the secondary markers (system_netmask /
# system_default_domain) BEFORE system_password, so the feed's bidirectional
# match is exercised against the harder ordering a real appliance may emit.
CONFIG_SNAPSHOT = (
    "system_hostname=barracuda\n"
    "system_netmask=255.255.255.0\n"
    "system_default_domain=example.com\n"
    "system_password=$1$aBcDeFgH$0123456789abcdefABCDEF.\n"
)

# The traversal payload as the appliance receives it (path + query), for both
# known CGI directories. self.path keeps the %00 / ../ sequences verbatim.
TRAVERSAL_SUFFIX = "/view_help.cgi?locale=/../../../../../../../mail/snapshot/config.snapshot%00"


class Handler(BaseHTTPRequestHandler):
    server_version = "BarracudaHTTP 4.0"
    sys_version = ""

    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Server", "BarracudaHTTP 4.0")
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        is_traversal = (
            self.path == "/cgi-mod" + TRAVERSAL_SUFFIX
            or self.path == "/cgi-bin" + TRAVERSAL_SUFFIX
        )
        if is_traversal:
            if VULN_MODE:
                self._send(200, CONFIG_SNAPSHOT)
            else:
                # Patched appliance sanitises the locale parameter.
                self._send(404, "Not Found")
            return
        # Any other path — appliance login landing page, no leaked content.
        self._send(200, "<html><title>Barracuda</title></html>", ct="text/html")

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
