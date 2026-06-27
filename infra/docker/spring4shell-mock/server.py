"""Mock Spring Framework — CVE-2022-22965 (Spring4Shell) behaviour."""
import os
from urllib.parse import urlparse, parse_qs

VULN_MODE = os.environ.get("SPRING_MODE", "patched") == "vuln"

SPRING4SHELL_MARKER = b"SPRING4SHELL_NOCTIS_CONFIRMED"
BINDING_ERROR = b'{"message":"Failed to convert value of type \'java.lang.String\' to required type"}'


def _has_classloader_param(body_str, query_str):
    return "class.module.classLoader" in body_str or "class.module.classLoader" in query_str


def _handler_class():
    from http.server import BaseHTTPRequestHandler

    class Spring4ShellHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def _read_body(self):
            length = int(self.headers.get("Content-Length", 0))
            return self.rfile.read(length).decode("utf-8", errors="replace") if length else ""

        def _send(self, status, body, content_type="application/json"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            parsed = urlparse(self.path)
            body = self._read_body()
            query = parsed.query or ""

            if _has_classloader_param(body, query):
                if VULN_MODE:
                    resp = b'{"status":"ok"}'
                    self._send(200, resp)
                else:
                    self._send(400, BINDING_ERROR)
            else:
                self._send(200, b'{"status":"ok"}')

        def do_GET(self):
            parsed = urlparse(self.path)
            path = parsed.path
            params = parse_qs(parsed.query)

            if path == "/spring-webshell.jsp":
                if VULN_MODE and params.get("pwd", [None])[0] == "noctis":
                    self._send(200, SPRING4SHELL_MARKER, "text/plain")
                else:
                    self._send(404, b"Not Found", "text/plain")
                return

            self._send(200, b"<html>Spring Application</html>", "text/html")

    return Spring4ShellHandler


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
    print(f"Spring4Shell mock on :80/:443 (mode={mode})", flush=True)
    threading.Thread(target=http_srv.serve_forever, daemon=True).start()
    https_srv.serve_forever()
