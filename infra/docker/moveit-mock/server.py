#!/usr/bin/env python3
import os, re, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("MOVEIT_MODE", "patched") == "vuln"

_lock = threading.Lock()
_injected_sessions = set()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
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

    def _parse_cookie(self, name):
        cookie_header = self.headers.get("Cookie", "")
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith(name + "="):
                return part.split("=", 1)[1]
        return None

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            self._send(200, "<html><title>MOVEit Transfer</title><body>MOVEit Transfer</body></html>", "text/html")
        else:
            self._send(404, "Not found")

    def do_POST(self):
        path = self.path.split("?")[0]
        body = self._read_body()

        if "moveitisapi.dll" in self.path:
            self._handle_moveit_api()
        elif path == "/guestaccess.aspx":
            self._handle_guest_access(body)
        elif path == "/api/v1/auth/token":
            self._handle_auth_token()
        else:
            self._send(404, "Not found")

    def _handle_moveit_api(self):
        sessvar1 = self.headers.get("X-siLock-SessVar1", "")

        if VULN_MODE:
            # Check for SQL injection and extract injected session ID
            m = re.search(r"VALUES\s*\('([^']+)'", sessvar1)
            if m:
                session_id = m.group(1)
                with _lock:
                    _injected_sessions.add(session_id)
            self._send(200, "OK")
        else:
            # Patched: reject SQL injection attempts
            sql_indicators = ["INSERT INTO", "SELECT ", "DROP ", "DELETE ", "';"]
            if any(kw in sessvar1.upper() for kw in [i.upper() for i in sql_indicators]):
                self._send(400, "Invalid input detected")
            else:
                self._send(200, "OK")

    def _handle_guest_access(self, body):
        if "Arg06=123" in body and "transaction=" not in body:
            # Return CSRF token
            html = '<html><body><input name="csrftoken" value="testcsrf123"></body></html>'
            self._send(200, html, "text/html")
        else:
            self._send(200, "OK")

    def _handle_auth_token(self):
        session_id = self._parse_cookie("ASP.NET_SessionId")
        with _lock:
            injected = session_id in _injected_sessions

        if VULN_MODE and injected:
            token = '{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.noctis.test","token_type":"Bearer","expires_in":3600}'
            self._send(200, token, "application/json")
        else:
            self._send(401, '{"error":"invalid_session"}', "application/json")


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
