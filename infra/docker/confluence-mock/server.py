"""Mock Atlassian Confluence — CVE-2022-26134 OGNL injection behaviour."""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("CONFLUENCE_MODE", "patched") == "vuln"


class ConfluenceHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _is_ognl(self):
        return "${" in self.path or "@java" in self.path or "%24%7B" in self.path

    def do_GET(self):
        if self._is_ognl():
            if VULN_MODE:
                # Vulnerable: evaluates OGNL and redirects to login
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1/login.action")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                # Patched: rejects the malformed URI with 400
                body = b'{"message":"Bad Request","status-code":400}'
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        else:
            body = b"Not Found"
            self.send_response(404)
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
    http_srv = HTTPServer(("0.0.0.0", 80), ConfluenceHandler)
    https_srv = _make_https_server(ConfluenceHandler, 443)
    print(f"Confluence mock on :80/:443 (mode={mode})", flush=True)
    threading.Thread(target=http_srv.serve_forever, daemon=True).start()
    https_srv.serve_forever()
