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
        if "/owa/auth/logon.aspx" in self.path or "/owa/" in self.path:
            body = b"<html><body>Outlook Web App - Microsoft Exchange Server</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if VULN_MODE and self._has_ssrf_cookie():
            # Vulnerable: exposes internal routing headers
            body = b"<!-- Exchange OWA -->"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-CalculatedBETarget", "EXCH01.internal.corp")
            self.send_header("X-FEServer", "EXCH-FE01")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            # Patched or no SSRF cookie: normal response without internal headers
            body = b"Unauthorized"
            self.send_response(401)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 443))
    print(f"Exchange mock running on :{port} (mode={'vuln' if VULN_MODE else 'patched'})")
    HTTPServer(("0.0.0.0", port), ExchangeHandler).serve_forever()
