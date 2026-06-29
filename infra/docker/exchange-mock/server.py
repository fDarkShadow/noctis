"""Mock Microsoft Exchange — CVE-2021-26855 ProxyLogon SSRF behaviour."""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("EXCHANGE_MODE", "vuln") == "vuln"


class ExchangeHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _has_ssrf_cookie(self):
        cookie = self.headers.get("Cookie", "")
        return "X-AnonResource-Backend" in cookie or "X-BEResource" in cookie

    def _send(self, code, body, ct="text/html", extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        has_ssrf = self._has_ssrf_cookie()

        # OWA login page — service detection only. Other /owa/ paths
        # (e.g. /owa/auth/x.js) fall through to the SSRF handler below.
        if "/owa/auth/logon.aspx" in self.path or self.path.rstrip("/") in ("/owa", ""):
            self._send(200, "<html><body>Outlook Web App - Microsoft Exchange Server</body></html>")
            return

        # ECP endpoint — path check takes priority over generic SSRF handler.
        # On a real vulnerable Exchange the SSRF cookie bypasses auth and gives
        # access to ECP. On a patched server ECP redirects to OWA login.
        if "/ecp/" in self.path:
            if VULN_MODE and has_ssrf:
                self._send(200, "Exchange Control Panel - ECP - msExchEcpCanary")
            else:
                # Patched: redirect to OWA (no auth bypass)
                self.send_response(302)
                self.send_header("Location", "/owa/auth/logon.aspx")
                self.send_header("Content-Length", "0")
                self.end_headers()
            return

        # Generic SSRF probe (e.g. /owa/auth/x.js with SSRF cookie):
        # vulnerable server leaks internal routing headers.
        if VULN_MODE and has_ssrf:
            self._send(
                200,
                "<!-- Exchange OWA -->",
                extra_headers={
                    "X-CalculatedBETarget": "EXCH01.internal.corp",
                    "X-FEServer": "EXCH-FE01",
                },
            )
            return

        self._send(401, "Unauthorized", ct="text/plain")

    def do_POST(self):
        self.do_GET()


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/app/cert.pem", "/app/key.pem")
    srv = HTTPServer(("0.0.0.0", port), ExchangeHandler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    mode = "vuln" if VULN_MODE else "patched"
    https = _make_https_server(443)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    HTTPServer(("0.0.0.0", 80), ExchangeHandler).serve_forever()
