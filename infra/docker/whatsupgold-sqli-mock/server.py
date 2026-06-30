#!/usr/bin/env python3
import json, os, re, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("WHATSUPGOLD_SQLI_MODE", "patched") == "vuln"

_state_lock = threading.Lock()
_alert_name = None


def _read_body(handler):
    length = int(handler.headers.get("Content-Length", 0))
    return handler.rfile.read(length) if length > 0 else b""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/NmConsole/Platform/Filter/AlertCenterItemsReportThresholds"):
            with _state_lock:
                name = _alert_name
            if VULN_MODE and name:
                self._send(200, json.dumps({"data": [{"DisplayName": name}]}))
            else:
                self._send(200, json.dumps({"data": []}))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        global _alert_name
        body = _read_body(self)

        if self.path.startswith("/NmConsole/WugSystemAppSettings/JMXSecurity"):
            resp = json.dumps({"initialized": True})
            resp_bytes = resp.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_bytes)))
            self.send_header("Set-Cookie", "ASP.NET_SessionId=noctis_session; Path=/; HttpOnly")
            self.end_headers()
            self.wfile.write(resp_bytes)

        elif self.path.startswith("/NmConsole/Platform/PerformanceMonitorErrors/HasErrors"):
            if VULN_MODE:
                try:
                    data = json.loads(body)
                    class_id = data.get("classId", "")
                    m = re.search(r"sAlertName='([^']+)'", class_id)
                    if m:
                        with _state_lock:
                            _alert_name = m.group(1)
                except Exception:
                    pass
                self._send(200, "true", "text/plain")
            else:
                self._send(400, json.dumps({"error": "bad request"}))
        else:
            self._send(404, json.dumps({"error": "not found"}))


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
