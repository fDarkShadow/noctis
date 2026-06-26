"""Mock Microsoft Exchange — CVE-2021-26855 ProxyLogon SSRF behaviour."""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("EXCHANGE_MODE", "vuln") == "vuln"


class ExchangeHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _has_ssrf_cookie(self):
        cookie = self.headers.get("Cookie", "")
        return "X-AnonResource-Backend" in cookie or "X-BEResource" in cookie

    def do_GET(self):
        # SSRF cookie check runs FIRST — the vulnerability bypasses normal routing.
        # On a real vulnerable Exchange, the SSRF cookie causes the frontend to
        # forward the request to an internal backend and expose routing headers.
        if VULN_MODE and self._has_ssrf_cookie():
            body = b"<!-- Exchange OWA -->"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-CalculatedBETarget", "EXCH01.internal.corp")
            self.send_header("X-FEServer", "EXCH-FE01")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # Normal OWA login page (no SSRF cookie or patched server)
        if "/owa/auth/logon.aspx" in self.path or "/owa/" in self.path:
            body = b"<html><body>Outlook Web App - Microsoft Exchange Server</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # ECP access (only reachable after SSRF confirms proxylogon_ssrf)
        if "/ecp/" in self.path:
            body = b"Exchange Control Panel - ECP"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        body = b"Unauthorized"
        self.send_response(401)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


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
    http_srv = HTTPServer(("0.0.0.0", 80), ExchangeHandler)
    https_srv = _make_https_server(ExchangeHandler, 443)
    print(f"Exchange mock on :80/:443 (mode={mode})", flush=True)
    threading.Thread(target=http_srv.serve_forever, daemon=True).start()
    https_srv.serve_forever()
