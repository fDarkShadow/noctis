#!/usr/bin/env python3
# Mock for CVE-2013-1965 (Apache Struts2 S2-012 — Showcase OGNL RCE).
# Ported detection target of OpenVAS NASL 2012/apache/gb_struts_s2-012_active.nasl.
#
# Both modes serve the Struts2 Showcase application realistically (the
# /struts2-showcase/showcase.action landing page), because patched Struts
# (>= 2.3.14.2) still ships Showcase — presence is only a precondition.
#
# Vuln mode:    POST /struts2-showcase/skill/save.action — when the form body
#               carries the S2-012 OGNL payload (currentSkill.name=%{...
#               _memberAccess ... ProcessBuilder ... echo RCEWorked ... }), the
#               server emulates OGNL/Java method execution and echoes the
#               executed output "RCEWorked" in the response body (HTTP 200).
#               A request WITHOUT the OGNL payload gets the ordinary skill page
#               with no marker — so the TP proves the payload matters.
# Patched mode: same Showcase pages, but skill/save.action never evaluates OGNL
#               and never echoes RCEWorked (returns the ordinary skill page) —
#               so the TN exercises the fix on a real, product-serving instance.
import os, ssl, threading, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("STRUTS_1965_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

SHOWCASE_BODY = (
    "<!DOCTYPE html>\n<html><head><title>Struts2 Showcase</title></head>\n"
    "<body><h1>>Struts Showcase<</h1>\n"
    "<a href=\"index.action\">Showcase</a>\n"
    "</body></html>\n"
)

SKILL_FORM_BODY = (
    "<!DOCTYPE html>\n<html><head><title>Skill - Struts2 Showcase</title></head>\n"
    "<body><h2>Save Skill</h2>\n"
    "<form action=\"save.action\" method=\"post\">\n"
    "<input type=\"text\" name=\"currentSkill.name\"/>\n"
    "<input type=\"text\" name=\"currentSkill.description\"/>\n"
    "</form></body></html>\n"
)


def _has_ognl_payload(raw_body):
    """True when the form carries an S2-012 OGNL injection in currentSkill.name."""
    try:
        decoded = urllib.parse.unquote_plus(raw_body.decode("utf-8", "replace"))
    except Exception:
        return False
    # The real OGNL S2-012 payload sets _memberAccess and spawns a ProcessBuilder.
    return ("_memberAccess" in decoded) and ("ProcessBuilder" in decoded)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Gate / precondition: Showcase landing page (served by BOTH modes).
        if self.path == "/struts2-showcase/showcase.action":
            self._send(200, SHOWCASE_BODY)
        else:
            self._send(404, "Not found")

    def do_POST(self):
        body = self._read_body()
        if self.path == "/struts2-showcase/skill/save.action":
            # Vulnerable Struts2 evaluates the injected OGNL and runs the command,
            # echoing its output. Only emit the marker when the payload is present.
            if VULN_MODE and _has_ognl_payload(body):
                self._send(200, "<html><body>" + SKILL_FORM_BODY + "\nRCEWorked\n</body></html>")
            else:
                # Patched instance (or a request without the payload): ordinary
                # skill page, OGNL is not evaluated, no marker echoed.
                self._send(200, SKILL_FORM_BODY)
        elif self.path == "/struts2-showcase/showcase.action":
            self._send(200, SHOWCASE_BODY)
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
