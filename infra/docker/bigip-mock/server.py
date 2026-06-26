"""Mock F5 BIG-IP iControl REST server — CVE-2022-1388 vulnerable behaviour."""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("BIGIP_MODE", "vuln") == "vuln"


class BigIPHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress default access log

    def _is_auth_bypassed(self):
        """Return True if the Connection header contains X-F5-Auth-Token (bypass)."""
        connection = self.headers.get("Connection", "")
        return "X-F5-Auth-Token" in connection

    def do_GET(self):
        if self.path.startswith("/mgmt/tm/sys"):
            if VULN_MODE and self._is_auth_bypassed():
                self._respond(200, {
                    "kind": "tm:sys:syscollectionstate",
                    "selfLink": "https://localhost/mgmt/tm/sys?ver=15.1.0",
                    "items": []
                })
            else:
                self._respond(401, {"code": 401, "message": "Authorization Required"})
        else:
            self._respond(404, {"code": 404, "message": "Not Found"})

    def do_POST(self):
        if self.path == "/mgmt/tm/util/bash":
            if VULN_MODE and self._is_auth_bypassed():
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                try:
                    req = json.loads(body)
                    cmd = req.get("utilCmdArgs", "-c id")
                except Exception:
                    cmd = "-c id"
                # Return simulated command output
                self._respond(200, {"kind": "tm:util:bash:runstate", "commandResult": "uid=0(root) gid=0(root) groups=0(root)\n"})
            else:
                self._respond(401, {"code": 401, "message": "Authorization Required"})
        else:
            self._respond(404, {"code": 404, "message": "Not Found"})

    def _respond(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


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
    http_srv = HTTPServer(("0.0.0.0", 80), BigIPHandler)
    https_srv = _make_https_server(BigIPHandler, 443)
    print(f"BIG-IP mock on :80/:443 (mode={mode})", flush=True)
    threading.Thread(target=http_srv.serve_forever, daemon=True).start()
    https_srv.serve_forever()
