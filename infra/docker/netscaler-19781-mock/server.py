#!/usr/bin/env python3
"""Mock Citrix ADC / NetScaler Gateway — CVE-2019-19781 directory traversal."""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("NETSCALER_MODE", "patched") == "vuln"

# smb.conf disclosed by the traversal on a vulnerable appliance. The "[global]"
# section header is the Nuclei/Metasploit matcher; the NOCTIS marker proves the
# response came from this mock.
SMB_CONF = (
    b"# NOCTIS_NETSCALER_CONFIRMED\n"
    b"[global]\n"
    b"\tencrypt passwords = yes\n"
    b"\tname resolve order = lmhosts wins host bcast\n"
)

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # The engine sends the literal "/vpn/../vpns/cfg/smb.conf" over raw TCP;
        # BaseHTTPRequestHandler does not normalise the path, so match verbatim.
        if self.path == "/vpn/../vpns/cfg/smb.conf":
            if VULN_MODE:
                self._send(200, SMB_CONF)
            else:
                # Patched: traversal is rejected, file never disclosed.
                self._send(403, b"HTTP/1.1 403 Forbidden\n")
        else:
            self._send(404, b"Not found")

    def do_POST(self):
        self._send(404, b"Not found")

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
