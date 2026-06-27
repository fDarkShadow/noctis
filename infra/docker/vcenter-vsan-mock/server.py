#!/usr/bin/env python3
import json
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("VCENTER_MODE", "patched") == "vuln"

VSAN_ENDPOINT = (
    "/ui/h5-vsan/rest/proxy/service/"
    "com.vmware.vsan.client.services.capability."
    "VsanCapabilityProvider/getClusterCapabilityData"
)

VSPHERE_LOGIN_PAGE = b"""<!DOCTYPE html>
<html><head><title>vSphere</title></head>
<body><div id="login"><h1>VMware vSphere</h1></div></body>
</html>"""


class VCenterHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, dict):
            body = json.dumps(body, separators=(",", ":")).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/ui"):
            self._send(200, VSPHERE_LOGIN_PAGE, ct="text/html")
        else:
            self._send(404, {"error": "Not Found"})

    def do_POST(self):
        if self.path == VSAN_ENDPOINT:
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)  # consume body
            if VULN_MODE:
                self._send(200, {
                    "result": {
                        "isDisconnected": False,
                        "providerList": [],
                        "clusterCapabilities": {}
                    }
                })
            else:
                self._send(401, {
                    "type": "com.vmware.vapi.std.errors.unauthenticated",
                    "value": {"messages": []}
                })
        else:
            self._send(404, {"error": "Not Found"})


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/certs/server.crt", "/certs/server.key")
    srv = HTTPServer(("0.0.0.0", port), VCenterHandler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    mode = "vuln" if VULN_MODE else "patched"
    https = _make_https_server(443)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    print(f"vCenter vSAN mock on :80/:443 (mode={mode})", flush=True)
    HTTPServer(("0.0.0.0", 80), VCenterHandler).serve_forever()
