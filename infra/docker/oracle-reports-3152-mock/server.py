#!/usr/bin/env python3
"""Mock for Oracle Reports rwservlet unauthenticated exposure (CVE-2012-3152).

  /reports/rwservlet/showenv
      vuln   : returns HTTP 200 with the genuine Reports Servlet environment
               dump (ORACLE_HOME, REPORTS_PATH, REPORTS_TMP, ...) — the real
               disclosure structure a vulnerable, unauthenticated Oracle Reports
               server returns. The feed keys on this genuine signature; no
               fabricated marker is required for the match.
      patched: returns HTTP 403 (the diagnostic command is rejected / requires
               authorisation on a hardened server), so every detection step
               fails and the scan reports nothing.

The SHOWENV disclosure is the detectable precondition of the arbitrary file
read; the mock never serves target file contents.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("ORACLE_REPORTS_MODE", "patched") == "vuln"

# Genuine Reports Servlet SHOWENV environment dump — the disclosure structure a
# vulnerable, unauthenticated Oracle Reports server returns.
SHOWENV_PAGE = (
    "<html><head><title>Reports Servlet Environment</title></head><body>"
    "<h1>Reports Servlet Environment Variables</h1>"
    "<table border=\"1\">"
    "<tr><th>Name</th><th>Value</th></tr>"
    "<tr><td>ORACLE_HOME</td><td>/u01/app/oracle/product/fmw/Oracle_BI1</td></tr>"
    "<tr><td>REPORTS_PATH</td><td>/u01/app/oracle/reports/templates</td></tr>"
    "<tr><td>REPORTS_TMP</td><td>/tmp</td></tr>"
    "<tr><td>REPORTS_SERVER</td><td>rep_wls_reports</td></tr>"
    "<tr><td>NLS_LANG</td><td>AMERICAN_AMERICA.AL32UTF8</td></tr>"
    "</table></body></html>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # rwservlet SHOWENV diagnostic command (case-insensitive path match).
        if self.path.lower().startswith("/reports/rwservlet/showenv"):
            if VULN_MODE:
                self._send(200, SHOWENV_PAGE)
            else:
                # Hardened/patched: command access denied.
                self._send(403, "Forbidden")
            return
        self._send(404, "Not found")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
