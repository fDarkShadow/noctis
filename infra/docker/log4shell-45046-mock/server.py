#!/usr/bin/env python3
"""Mock Log4j2 app for CVE-2021-45046 (incomplete-fix follow-up to Log4Shell).

vuln    → Log4j 2.15.0 (fixed 2021-44228 but still affected by 2021-45046),
          fires a JNDI LDAP callback when a payload appears in a request header.
patched → Log4j 2.16.0, never calls back.
"""
import os
import re
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("LOG4J45046_MODE", "patched") == "vuln"

VULN_VERSION = "2.15.0"
PATCHED_VERSION = "2.16.0"

POM_PATH = "/META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties"
POM_TEMPLATE = (
    "groupId=org.apache.logging.log4j\n"
    "artifactId=log4j-core\n"
    "version={version}\n"
)

_JNDI_RE = re.compile(r'\$\{jndi:ldap://([^/\}]+)/([^}\s]+)\}', re.IGNORECASE)


def _jndi_callback(headers):
    """Fire an HTTP callback for any JNDI LDAP payload found in request headers."""
    for key in headers:
        m = _JNDI_RE.search(headers[key])
        if m:
            host_port, token = m.group(1), m.group(2)
            try:
                urllib.request.urlopen(f"http://{host_port}/{token}", timeout=5)
            except Exception:
                pass


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if VULN_MODE:
            _jndi_callback(self.headers)

        path = self.path.split("?")[0]
        if path == POM_PATH:
            version = VULN_VERSION if VULN_MODE else PATCHED_VERSION
            self._send(200, POM_TEMPLATE.format(version=version))
        else:
            self._send(200, "OK\n")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
