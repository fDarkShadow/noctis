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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 443))
    print(f"BIG-IP mock running on :{port} (mode={'vuln' if VULN_MODE else 'patched'})")
    HTTPServer(("0.0.0.0", port), BigIPHandler).serve_forever()
