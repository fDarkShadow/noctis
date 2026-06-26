"""Mock PHP-CGI server — CVE-2024-4577 argument injection behaviour."""
import os
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("PHP_CGI_MODE", "vuln") == "vuln"

PHP_CGI_PATHS = {
    "/cgi-bin/php-cgi.exe",
    "/php-cgi.exe",
    "/cgi-bin/php.exe",
    "/php-cgi/php-cgi.exe",
}

MARKER = b"NOCTIS_PHP_CGI_CONFIRMED"


class PhpCgiHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _is_php_cgi_path(self, path):
        return path in PHP_CGI_PATHS

    def _has_arg_injection(self, raw_query):
        """Check for %AD (soft-hyphen) arg injection trigger — case insensitive."""
        return "%ad" in raw_query.lower()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parsed.query

        if not self._is_php_cgi_path(path):
            self._respond(404, b"Not Found")
            return

        if not VULN_MODE:
            self._respond(400, b"Bad Request")
            return

        if not self._has_arg_injection(query):
            self._respond(400, b"Bad Request")
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""

        # Simulate PHP execution: if body echoes the confirmation marker, return it
        if b"NOCTIS_PHP_CGI_CONFIRMED" in body:
            self._respond(200, MARKER)
        else:
            self._respond(200, b"")

    def do_GET(self):
        self._respond(200, b"PHP mock running")

    def _respond(self, code, body):
        self.send_response(code)
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
    http_srv = HTTPServer(("0.0.0.0", 80), PhpCgiHandler)
    https_srv = _make_https_server(PhpCgiHandler, 443)
    print(f"PHP-CGI mock on :80/:443 (mode={mode})", flush=True)
    threading.Thread(target=http_srv.serve_forever, daemon=True).start()
    https_srv.serve_forever()
