#!/usr/bin/env python3
import os, ssl, threading, json, re, base64
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

VULN_MODE = os.environ.get("CPANEL_MODE", "patched") == "vuln"

# Fixed session token used for all test sessions (deterministic, no cookie jar needed)
FIXED_SESSION = "NOCTIS_TEST"

# In-memory session store: token → {hasroot: bool}
SESSIONS = {}
SESSIONS_LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain", extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""

    def _session_from_cookie(self):
        cookie = self.headers.get("Cookie", "")
        m = re.search(r'whostmgrsession=([^;%]+)', cookie)
        return m.group(1) if m else None

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/login/" and "login_only=1" in (parsed.query or ""):
            self._read_body()
            session_data = {"hasroot": False}
            auth = self.headers.get("Authorization", "")
            if VULN_MODE and auth.startswith("Basic "):
                try:
                    # CRLF injection: attacker embeds hasroot=1 in the base64-encoded header
                    decoded = base64.b64decode(auth[6:]).decode("latin-1")
                    if "hasroot=1" in decoded:
                        session_data["hasroot"] = True
                except Exception:
                    pass
            with SESSIONS_LOCK:
                SESSIONS[FIXED_SESSION] = session_data
            self._send(
                401,
                "Login failed for user: root",
                extra_headers={"Set-Cookie": f"whostmgrsession={FIXED_SESSION}%2C0%2C0; Path=/"}
            )
        else:
            self._send(404, "Not found")

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/":
            tok = self._session_from_cookie()
            with SESSIONS_LOCK:
                data = SESSIONS.get(tok, {})
            if data.get("hasroot"):
                self._send(307, "", extra_headers={"Location": "/cpsess9999999999/"})
            else:
                self._send(401, "Not authenticated")

        elif re.match(r"^/cpsess\d+/json-api/version", path):
            tok = self._session_from_cookie()
            with SESSIONS_LOCK:
                data = SESSIONS.get(tok, {})
            if data.get("hasroot"):
                self._send(
                    200,
                    json.dumps({
                        "data": {"version": "11.126.0.10"},
                        "command": "version",
                        "reason": "OK",
                        "result": 1
                    }),
                    "application/json"
                )
            else:
                self._send(
                    401,
                    json.dumps({"reason": "Access denied", "result": 0}),
                    "application/json"
                )

        else:
            self._send(401, "Access denied")


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
