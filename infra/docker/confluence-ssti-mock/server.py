"""Mock Atlassian Confluence — CVE-2023-22527 Velocity SSTI behaviour."""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("CONFLUENCE_MODE", "patched") == "vuln"

SSTI_MARKERS = ("#set", "@java", "getRuntime", "forName", "class.for", "velocity")


class ConfluenceSStiHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length).decode("utf-8", errors="replace") if length else ""

    def _is_velocity_payload(self, body):
        low = body.lower()
        return any(m in low for m in SSTI_MARKERS)

    def _send(self, status, body_bytes, content_type="text/plain"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def do_POST(self):
        body = self._read_body()
        if self.path.startswith("/_domobjects/"):
            if self._is_velocity_payload(body):
                if VULN_MODE:
                    resp = b"NOCTIS_CONFLUENCE_SSTI_CONFIRMED"
                    self._send(200, resp)
                else:
                    resp = b'{"message":"Request not permitted","status-code":403}'
                    self._send(403, resp, "application/json")
            else:
                self._send(404, b"Not Found")
        else:
            self._send(404, b"Not Found")

    def do_GET(self):
        self._send(404, b"Not Found")


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
    http_srv = HTTPServer(("0.0.0.0", 80), ConfluenceSStiHandler)
    https_srv = _make_https_server(ConfluenceSStiHandler, 443)
    print(f"Confluence SSTI mock on :80/:443 (mode={mode})", flush=True)
    threading.Thread(target=http_srv.serve_forever, daemon=True).start()
    https_srv.serve_forever()
