"""Mock Shellshock-vulnerable CGI server — CVE-2014-6271."""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("SHELLSHOCK_MODE", "vuln") == "vuln"

SHELLSHOCK_PREFIX = "() { :; };"
MARKER = "NOCTIS_SHELLSHOCK_9841_CONFIRMED"

CGI_PATHS = {
    "/cgi-bin/test.cgi", "/cgi-bin/status", "/cgi-bin/env.cgi",
    "/cgi-bin/printenv", "/cgi-bin/test-cgi", "/cgi-bin/info.sh",
    "/cgi-bin/index.cgi", "/cgi-bin/login.cgi", "/cgi-bin/vulnerable",
    "/cgi-bin/stats", "/victim.cgi", "/cgi-bin/shockme.cgi",
    "/cgi-sys/defaultwebpage.cgi", "/cgi-bin/php.cgi", "/cgi-bin/bash",
}


class ShellshockHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _has_shellshock_payload(self):
        for hdr in ("User-Agent", "Referer", "Cookie"):
            val = self.headers.get(hdr, "")
            if SHELLSHOCK_PREFIX in val:
                return True
        return False

    def _is_cgi_path(self):
        path = self.path.split("?")[0]
        return path in CGI_PATHS

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def _handle(self):
        if VULN_MODE and self._is_cgi_path() and self._has_shellshock_payload():
            body = (MARKER + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b"OK\n"
            self.send_response(200)
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
    http_srv = HTTPServer(("0.0.0.0", 80), ShellshockHandler)
    https_srv = _make_https_server(ShellshockHandler, 443)
    print(f"Shellshock mock on :80/:443 (mode={mode})", flush=True)
    threading.Thread(target=http_srv.serve_forever, daemon=True).start()
    https_srv.serve_forever()
