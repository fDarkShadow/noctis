#!/usr/bin/env python3
"""Mock for NUUO NVR devices — shared across multiple CVEs.

Consumers:
  * CVE-2018-1150 — NVRMini2 backdoor, unauthenticated account disclosure via
    GET /users_xml.php.
    Ported from OpenVAS NASL 2018/nuuo/gb_nuuo_nvr_backdoor_active.nasl (GPL-2.0-only).
  * CVE-2016-6553 — NUUO NVR default credentials. The web login issues a
    PHPSESSID to any client; POST /login.php with the default creds authenticates
    the session, and GET /setting.php then returns the authenticated-area device
    markers (productName / official_fw_ver). A patched device serves the same
    product (same cookies, same pages) but rejects the default creds, so the
    session never authenticates and /setting.php withholds the markers.
    Ported from OpenVAS NASL 2016/gb_nuuo_devices_default_http_login.nasl (GPL-2.0-only).

Each endpoint is an independent branch — do not change one when editing another.
"""
import os, re, ssl, threading, uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("NUUO_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

# Default NUUO web credentials checked by the NASL.
DEFAULT_USER = "admin"
DEFAULT_PASS = "admin"

# Server-side session store: PHPSESSID -> authenticated(bool). Shared by the
# HTTP and HTTPS listeners in this process; requests are served sequentially.
_SESSIONS = {}
_SESSIONS_LOCK = threading.Lock()

# Login page shown to any client; carries the loginfail marker when a login was
# rejected (NASL treats absence of "cmd=loginfail" as a successful login).
_LOGIN_PAGE = ("<html><head><title>NUUO Network Video Recorder</title></head>"
               "<body><form action=\"login.php\" method=\"post\">"
               "<input name=\"user\"><input name=\"pass\" type=\"password\">"
               "</form></body></html>")
_LOGIN_FAIL_PAGE = ("<html><head><title>NUUO Network Video Recorder</title></head>"
                    "<body>Login failed"
                    "<script>location.href='login.php?cmd=loginfail';</script>"
                    "</body></html>")
# Authenticated-only settings page with the NUUO device markers the NASL greps.
_SETTING_PAGE = ("<html><head><title>NUUO Setting</title></head><body>"
                 "<span class=\"productName\">NUUO NVRmini2</span>"
                 "<div id=\"official_fw_ver\">03.06.02</div>"
                 "</body></html>")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ct="text/plain", extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(n).decode("utf-8", "replace") if n else ""

    def _sid(self):
        m = re.search(r"PHPSESSID=([^;\s]+)", self.headers.get("Cookie", "") or "")
        return m.group(1) if m else None

    def do_GET(self):
        # CVE-2018-1150 — backdoor account disclosure
        if VULN_MODE and self.path == "/users_xml.php":
            xml = ("<Response><AccountInfo>"
                   "<User><Name>guest</Name><Privilege>1</Privilege></User>"
                   "<User><Name>operator</Name><Privilege>2</Privilege></User>"
                   "</AccountInfo></Response>")
            self._send(200, xml, ct="text/xml")
        # CVE-2016-6553 — web root issues a PHPSESSID to any client (precondition
        # only). Served identically by vuln and patched devices.
        elif self.path == "/" or self.path.startswith("/index"):
            sid = self._sid() or uuid.uuid4().hex
            with _SESSIONS_LOCK:
                _SESSIONS.setdefault(sid, False)
            self._send(200, _LOGIN_PAGE, ct="text/html",
                       extra_headers={"Set-Cookie": "PHPSESSID=%s; path=/" % sid})
        # CVE-2016-6553 — authenticated-only settings page. The device markers are
        # returned only for a session that authenticated with the default creds;
        # an unauthenticated session is bounced back to the login page.
        elif self.path.startswith("/setting.php"):
            sid = self._sid()
            with _SESSIONS_LOCK:
                authed = bool(sid and _SESSIONS.get(sid))
            if authed:
                self._send(200, _SETTING_PAGE, ct="text/html")
            else:
                self._send(200, _LOGIN_FAIL_PAGE, ct="text/html")
        else:
            self._send(404, "Not found")

    def do_POST(self):
        # CVE-2016-6553 — default credentials on the NVR web login.
        if self.path == "/login.php":
            body = self._body()
            sid = self._sid() or uuid.uuid4().hex
            params = dict(p.split("=", 1) for p in body.split("&") if "=" in p)
            creds_ok = (params.get("user") == DEFAULT_USER and
                        params.get("pass") == DEFAULT_PASS)
            if VULN_MODE and creds_ok:
                # Default creds still accepted -> authenticate this session.
                with _SESSIONS_LOCK:
                    _SESSIONS[sid] = True
                self._send(200, _LOGIN_PAGE, ct="text/html",
                           extra_headers={"Set-Cookie": "PHPSESSID=%s; path=/" % sid})
            else:
                # Patched device (or wrong creds) -> reject; loginfail marker set,
                # session stays unauthenticated.
                with _SESSIONS_LOCK:
                    _SESSIONS.setdefault(sid, False)
                self._send(200, _LOGIN_FAIL_PAGE, ct="text/html",
                           extra_headers={"Set-Cookie": "PHPSESSID=%s; path=/" % sid})
        else:
            self._send(404, "Not found")


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(CERT_DIR, "server.crt"), os.path.join(CERT_DIR, "server.key"))
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    if PORT_HTTPS:
        threading.Thread(target=lambda: _make_https_server(PORT_HTTPS).serve_forever(), daemon=True).start()
    if PORT_HTTP:
        HTTPServer(("0.0.0.0", PORT_HTTP), Handler).serve_forever()
    else:
        threading.Event().wait()
