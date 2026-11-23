#!/usr/bin/env python3
"""Mock for Open Web Analytics < 1.5.5 password-reset SQL injection (CVE-2014-1206).

The exploit (OpenVAS gb_open_web_analytics_sql_inj_vuln.nasl) POSTs a UNION ALL SELECT
into the owa_email_address parameter of /index.php?owa_do=base.passwordResetForm. The
payload wraps the leaked column between MySQL hex markers:
  CONCAT(0x7177766871, 0x73716c2d696e6a2d74657374, <password>, 0x7176627971)
  = 'qwvhq' + 'sql-inj-test' + <password> + 'qvbyq'

Vuln mode: ONLY when the body actually carries the UNION injection (the SELECT plus the
  0x73716c2d696e6a2d74657374 marker) does the mock behave like a real vulnerable build —
  MySQL decodes the hex server-side and the decoded marker chain comes back inside an
  "Invalid address:" error. This proves the payload matters (the TP keys on executed SQL,
  not on an unconditional echo).
Patched mode: the endpoint still exists and still returns an "Invalid address:" error for
  a malformed address, but it reflects the RAW submitted input verbatim (the hex is never
  decoded). The raw input contains 0x73716c2d696e6a2d74657374, not 'sql-inj-test', so the
  feed's 'qwvhqsql-inj-test' match can never fire — a faithful true-negative on a real,
  non-vulnerable instance of the product.
"""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

VULN_MODE = os.environ.get("OWA_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

RESET_PATH = "/index.php?owa_do=base.passwordResetForm"
# Markers from the NASL payload's CONCAT(...).
INJ_MARKER_HEX = "0x73716c2d696e6a2d74657374"  # 'sql-inj-test'
# A plausible leaked password hash, as a real UNION extraction would surface.
LEAKED_PASSWORD = "5f4dcc3b5aa765d61d8327deb882cf99"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != RESET_PATH:
            self._send(404, "Not found")
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        params = parse_qs(raw, keep_blank_values=True)
        email = (params.get("owa_email_address") or [""])[0]

        if VULN_MODE:
            # A vulnerable build runs the injected SQL. Only emit the decoded marker chain
            # when the request actually contains the UNION injection with the hex marker —
            # otherwise behave like a normal validation error.
            if "UNION ALL SELECT" in raw.upper() and INJ_MARKER_HEX in raw:
                decoded = "qwvhq" + "sql-inj-test" + LEAKED_PASSWORD + "qvbyq"
                self._send(
                    200,
                    "<html><body><p>Invalid address: %s</p></body></html>" % decoded,
                )
            else:
                self._send(
                    200,
                    "<html><body><p>Invalid address: %s</p></body></html>" % email,
                )
        else:
            # Patched build: still reports an invalid address, but reflects the raw input
            # verbatim (no SQL executed, hex never decoded).
            self._send(
                200,
                "<html><body><p>Invalid address: %s</p></body></html>" % email,
            )

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
