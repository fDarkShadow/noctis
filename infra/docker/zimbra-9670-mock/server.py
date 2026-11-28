#!/usr/bin/env python3
"""Inert mock for CVE-2019-9670 (Zimbra Collaboration Autodiscover XXE -> file read).

Cyber-safety: this mock performs NO real XML entity resolution and reads NO real
file. In vuln mode it discloses a single hard-coded, FABRICATED, inert sentinel
line (a fake benign account entry) and ONLY when the incoming request actually
carries an external-entity DOCTYPE whose declared entity is referenced in the
body. A benign Autodiscover request, or one without the external entity, never
produces the sentinel -- so a blanket-discloser / constant mock is caught by the
negative control.
"""
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("ZIMBRA_9670_MODE", "patched") == "vuln"

AUTODISCOVER_PATH = "/autodiscover/autodiscover.xml"

# FABRICATED, inert sentinel -- NOT a real /etc/passwd line and not a real secret.
# Its signature only appears in a response when the external entity was processed.
SENTINEL = "nxtest-xxe:x:0:0:NOCTIS_ZIMBRA_XXE_CONFIRMED:/nonexistent:/sbin/nologin"

# Declares an external SYSTEM entity pointing at a file:// (or other) resource.
_ENTITY_DECL = re.compile(
    rb"<!ENTITY\s+(\w+)\s+SYSTEM\s+[\"']\s*(?:file|http|https|ftp|php|expect)://",
    re.IGNORECASE,
)

SAFE_BODY = (
    b'<?xml version="1.0"?>'
    b"<Autodiscover><Response><Error>Invalid request</Error></Response></Autodiscover>"
)

PATCHED_BODY = (
    b'<?xml version="1.0"?>'
    b"<Autodiscover><Response><Error>External entities are not permitted</Error>"
    b"</Response></Autodiscover>"
)


def _disclosed_body(sentinel):
    # Simulates the vulnerable server echoing the resolved entity value
    # (the fabricated sentinel) inside the AcceptableResponseSchema element.
    body = (
        '<?xml version="1.0"?>'
        '<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">'
        "<Response><Account><AcceptableResponseSchema>"
        + sentinel
        + "</AcceptableResponseSchema></Account></Response></Autodiscover>"
    )
    return body.encode()


def _entity_resolved(raw):
    """True only when an external entity is declared AND referenced in the body.

    This is what makes detection entity-sensitive: a well-formed Autodiscover
    request without the external-entity DOCTYPE returns no sentinel.
    """
    m = _ENTITY_DECL.search(raw)
    if not m:
        return False
    name = m.group(1)
    return (b"&" + name + b";") in raw


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/xml"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def do_POST(self):
        path = self.path.split("?")[0]
        if path.lower() != AUTODISCOVER_PATH:
            self._send(404, b"Not found")
            return

        raw = self._read_body()

        if VULN_MODE:
            if _entity_resolved(raw):
                # Vulnerable: external entity "resolved" -> fabricated sentinel disclosed.
                self._send(200, _disclosed_body(SENTINEL))
            else:
                # No external entity in the request -> nothing disclosed.
                self._send(200, SAFE_BODY)
        else:
            # Patched: entity never resolved, regardless of request content.
            self._send(200, PATCHED_BODY)

    def do_GET(self):
        self._send(404, b"Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
