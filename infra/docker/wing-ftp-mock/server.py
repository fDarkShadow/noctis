#!/usr/bin/env python3
"""Mock for CVE-2015-4107 — Wing FTP Server <= 4.3.8 Authenticated Command Execution.

Ported from OpenVAS/Greenbone NASL 2014/wing_ftp/gb_wing_ftp_server_command_exec_vuln.nasl
(GPL-2.0-only, Greenbone Community Feed).

Reproduces the admin web console auth-then-exploit flow:
  POST /admin_login.html       username/password → on success sets a UIDADMIN session cookie
  POST /admin_lua_script.html  (authenticated) executes Lua; os.execute / print run arbitrary code

Vuln mode: the Lua console evaluates the supplied code and returns its output — so a
`print("a" .. "b")` payload comes back as the concatenated string `ab`, proving execution.
Patched mode: the Lua console is removed (403), so the exploit yields no marker.
Both modes reject wrong credentials (no session cookie issued).
"""
import hashlib
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

from mocklib import serve  # provided by noctis/py-mock-base

VULN_MODE = os.environ.get("CVE_2015_4107_MODE", "patched") == "vuln"

# Admin credentials the mock accepts (supplied out of band by the operator; the
# inventory passes the same values as noctis_credentials).
EXPECTED_USER = os.environ.get("WING_ADMIN_USER", "admin")
EXPECTED_PASS = os.environ.get("WING_ADMIN_PASS", "wingftp-admin-pw")


def _session_token(user, password):
    """Deterministic session token for valid credentials (no shared state needed)."""
    return hashlib.md5(f"{user}:{password}".encode()).hexdigest()[:16]


VALID_TOKEN = _session_token(EXPECTED_USER, EXPECTED_PASS)

# print("literal" .. "literal" .. ...) — only quoted string literals joined by `..`.
_PRINT_RE = re.compile(r'print\s*\((.*)\)', re.DOTALL)
_STRLIT_RE = re.compile(r'"([^"]*)"')


def _eval_lua_print(command):
    """Evaluate a restricted `print("a" .. "b")` of string literals; None otherwise."""
    m = _PRINT_RE.search(command)
    if not m:
        return None
    arg = m.group(1)
    parts = [p for p in arg.split("..")]
    out = []
    for p in parts:
        lit = _STRLIT_RE.search(p)
        if not lit:
            return None
        out.append(lit.group(1))
    return "".join(out)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, extra_headers=None, ct="text/html"):
        if isinstance(body, str):
            body = body.encode("latin-1", "replace")
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(length).decode("latin-1") if length else ""

    def _cookie_token(self):
        cookie = self.headers.get("Cookie", "")
        m = re.search(r"UIDADMIN=([0-9a-fA-F]+)", cookie)
        return m.group(1) if m else None

    def _handle_login(self, form):
        user = (form.get("username") or [""])[0]
        password = (form.get("password") or [""])[0]
        if user == EXPECTED_USER and password == EXPECTED_PASS:
            # Successful admin login → issue the session cookie.
            self._send(
                200,
                "<html>Wing FTP Server Administrator</html>\n",
                extra_headers={"Set-Cookie": f"UIDADMIN={VALID_TOKEN}; path=/"},
            )
        else:
            # Wrong credentials → login page again, no cookie.
            self._send(200, "<html>Login failed</html>\n")

    def _handle_lua(self, form):
        # Authenticated admin Lua console.
        if self._cookie_token() != VALID_TOKEN:
            self._send(401, "<html>Not authenticated</html>\n")
            return
        if not VULN_MODE:
            # Patched build removes the arbitrary-command Lua console.
            self._send(403, "<html>Lua console disabled</html>\n")
            return
        command = (form.get("command") or [""])[0]
        output = _eval_lua_print(command)
        if output is None:
            self._send(200, "<html><pre></pre></html>\n")
        else:
            self._send(200, f"<html><pre>{output}</pre></html>\n")

    def do_POST(self):
        form = parse_qs(self._read_body())
        if self.path.startswith("/admin_login.html"):
            self._handle_login(form)
        elif self.path.startswith("/admin_lua_script.html"):
            self._handle_lua(form)
        else:
            self._send(404, "Not found\n", ct="text/plain")

    def do_GET(self):
        if self.path.startswith("/admin_login.html"):
            self._send(200, "<html>Wing FTP Server Administrator - Login</html>\n")
        else:
            self._send(404, "Not found\n", ct="text/plain")


if __name__ == "__main__":
    serve(Handler, HTTPServer)  # HTTP:80 + HTTPS:443 (cert from the base image)
