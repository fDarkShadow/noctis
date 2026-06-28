#!/usr/bin/env python3
import os, re, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote

VULN_MODE = os.environ.get("CRUSHFTP_MODE", "patched") == "vuln"
AUTH_TOKEN = "abc123xyz"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/xml"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            return self.rfile.read(length).decode("utf-8", errors="replace")
        return ""

    def do_GET(self):
        if self.path.startswith("/WebInterface/") or self.path == "/WebInterface":
            html = b"<html><title>CrushFTP WebInterface</title><body>CrushFTP</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(html)))
            self.send_header("Set-Cookie", f"currentAuth={AUTH_TOKEN}; Path=/")
            self.end_headers()
            self.wfile.write(html)
        else:
            self._send(404, "<error>Not found</error>")

    def do_POST(self):
        self._read_body()
        parsed = urlparse(self.path)

        if parsed.path.startswith("/WebInterface/function/"):
            params = parse_qs(parsed.query, keep_blank_values=True)
            command = params.get("command", [""])[0]
            path_param = unquote(params.get("path", [""])[0])

            if command == "zip" and "<INCLUDE>" in path_param:
                if VULN_MODE:
                    m = re.search(r"<INCLUDE>([^<]+)</INCLUDE>", path_param)
                    if m:
                        file_path = m.group(1)
                        try:
                            with open(file_path, "r") as f:
                                content = f.read()
                            xml = f'<?xml version="1.0"?><zip>{content}</zip>'
                            self._send(200, xml)
                            return
                        except Exception:
                            pass
                    self._send(500, "<?xml version='1.0'?><error>read failed</error>")
                else:
                    self._send(403, "<?xml version='1.0'?><error>Access denied</error>")
            else:
                self._send(404, "<?xml version='1.0'?><error>Unknown command</error>")
        else:
            self._send(404, "<error>Not found</error>")


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/certs/server.crt", "/certs/server.key")
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    https = _make_https_server(443)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
