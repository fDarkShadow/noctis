#!/usr/bin/env python3
"""Minimal Jenkins mock (HTTP 80 + HTTPS 443). vuln: anon /api/json; patched: 403.

Shared by general/jenkins-anonymous (/api/json) and jenkins/CVE-2017-1000353
(X-Jenkins version on every response + reachable /cli). Add branches, never change
an existing endpoint's status or body.
"""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
VULN = os.environ.get("JK_MODE", "patched") == "vuln"
# Real Jenkins sends X-Jenkins on every response; CVE-2017-1000353 is fixed in 2.57.
JENKINS_VERSION = "2.46.1" if VULN else "2.57"
API = ('{"_class":"hudson.model.Hudson","mode":"NORMAL","nodeName":"",'
       '"jobs":[{"_class":"hudson.model.FreeStyleProject","name":"deploy"}]}')
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _s(self, code, body):
        b = body.encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("X-Jenkins", JENKINS_VERSION); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if VULN and self.path.startswith("/api/json"):
            self._s(200, API)
        elif VULN and self.path.split("?")[0] == "/cli":
            # Remoting CLI endpoint exposed (pre-auth deserialization prerequisite).
            self._s(200, '{"cli":"Jenkins CLI"}')
        else:
            self._s(403, '{"error":"Authentication required"}')
def _https(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain("/certs/server.crt", "/certs/server.key")
    srv = HTTPServer(("0.0.0.0", port), H); srv.socket = ctx.wrap_socket(srv.socket, server_side=True); return srv
if __name__ == "__main__":
    try: threading.Thread(target=_https(443).serve_forever, daemon=True).start()
    except Exception: pass
    HTTPServer(("0.0.0.0", int(os.environ.get("JK_PORT", "80"))), H).serve_forever()
