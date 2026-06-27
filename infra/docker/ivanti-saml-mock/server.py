"""Mock Ivanti Connect Secure — CVE-2024-21893 SAML SSRF behaviour."""
import os
import re

VULN_MODE = os.environ.get("IVANTI_MODE", "patched") == "vuln"

RETRIEVAL_METHOD_RE = re.compile(
    r'<(?:\w+:)?RetrievalMethod[^>]+URI=["\']([^"\']+)["\']', re.IGNORECASE
)

IVANTI_RESPONSE = (
    b'<html><head><link rel="stylesheet" href="/dana-na/css/WriteCSS.css"/>'
    b'</head><body><a href="/dana-na/auth/url_default/welcome.cgi">Login</a>'
    b"<script>WriteCSS();</script></body></html>"
)


def _extract_uri(body_str):
    m = RETRIEVAL_METHOD_RE.search(body_str)
    return m.group(1) if m else None


def _ssrf_fetch(uri):
    """Attempt outbound HTTP request (simulates SSRF — for OOB testing)."""
    try:
        import urllib.request
        urllib.request.urlopen(uri, timeout=4)
    except Exception:
        pass


def _handler_class():
    from http.server import BaseHTTPRequestHandler

    class IvantiSAMLHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def _read_body(self):
            length = int(self.headers.get("Content-Length", 0))
            return self.rfile.read(length).decode("utf-8", errors="replace") if length else ""

        def _send(self, status, body, content_type="text/html"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if self.path.rstrip("/") != "/dana-ws/saml20.ws":
                self._send(404, b"Not Found", "text/plain")
                return

            body = self._read_body()
            uri = _extract_uri(body)

            if uri is None:
                self._send(400, b"<error>Invalid SAML request</error>", "text/xml")
                return

            if not VULN_MODE:
                self._send(400, b"<error>SAML validation failed</error>", "text/xml")
                return

            # Vulnerable: follow the RetrievalMethod URI (SSRF), return Ivanti markers
            _ssrf_fetch(uri)
            self._send(200, IVANTI_RESPONSE)

        def do_GET(self):
            self._send(302, b"", "text/plain")

    return IvantiSAMLHandler


def _make_https_server(handler, port):
    import ssl
    from http.server import HTTPServer
    srv = HTTPServer(("0.0.0.0", port), handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/app/cert.pem", "/app/key.pem")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    import threading
    from http.server import HTTPServer
    handler = _handler_class()
    mode = "vuln" if VULN_MODE else "patched"
    http_srv = HTTPServer(("0.0.0.0", 80), handler)
    https_srv = _make_https_server(handler, 443)
    print(f"Ivanti SAML mock on :80/:443 (mode={mode})", flush=True)
    threading.Thread(target=http_srv.serve_forever, daemon=True).start()
    https_srv.serve_forever()
