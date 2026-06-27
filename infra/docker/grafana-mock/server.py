"""Mock Grafana 8.x — CVE-2021-43798 plugin path traversal behaviour."""
import os
import posixpath

VULN_MODE = os.environ.get("GRAFANA_MODE", "patched") == "vuln"

FAKE_PASSWD = b"root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
FAKE_DEFAULTS_INI = b"[paths]\ndata = /var/lib/grafana\nlogs = /var/log/grafana\n[server]\nprotocol = http\nhttp_port = 3000\n[database]\ntype = sqlite3\n"


def _resolve_traversal(raw_path):
    parts = raw_path.split("?")[0]
    return posixpath.normpath(parts)


def _handler_class():
    from http.server import BaseHTTPRequestHandler

    class GrafanaHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def _send(self, status, body, content_type="text/plain"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            raw = self.path
            if ".." in raw:
                if not VULN_MODE:
                    self._send(400, b"Bad Request")
                    return
                resolved = _resolve_traversal(raw)
                if resolved == "/etc/passwd":
                    self._send(200, FAKE_PASSWD)
                elif "defaults.ini" in resolved:
                    self._send(200, FAKE_DEFAULTS_INI)
                else:
                    self._send(200, FAKE_PASSWD)
                return

            if raw.startswith("/public/plugins/"):
                self._send(200, b"<html>Grafana plugin static file</html>", "text/html")
                return

            self._send(302, b"Found", "text/plain")

    return GrafanaHandler


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
    print(f"Grafana mock on :80/:443 (mode={mode})", flush=True)
    threading.Thread(target=http_srv.serve_forever, daemon=True).start()
    https_srv.serve_forever()
