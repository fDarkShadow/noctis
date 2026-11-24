#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("CIVICRM_MODE", "patched") == "vuln"

# Marker reflected by the injected UNION SELECT, per the OpenVAS plugin.
MARKER = "sql-injection-test"

# The exact concat(0x...) marker column the NASL payload injects. The vuln branch
# reflects the marker ONLY when the request actually carries this literal, so the
# mock exercises the real payload instead of being self-fulfilling.
PAYLOAD_SIG = "union%20select"
CONCAT_SIG = "concat(0x673716c2d696e6a656374696f6e2d74657374)"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = self.path
        pl = p.lower()
        # CiviCRM jqState AJAX endpoint — the injectable parameter.
        if "page=civicrm" in pl and "civicrm/ajax/jqstate" in pl:
            has_payload = PAYLOAD_SIG in pl and CONCAT_SIG in pl
            if VULN_MODE and has_payload:
                # Vulnerable: the real UNION SELECT reflects the marker into output.
                # The `name` field (NASL extra_check) is present in both modes.
                self._send(200, '{"name":"%s"}' % MARKER, ct="application/json")
            else:
                # Patched, or a request without the real injection: the `name`
                # field is still present but the marker is never reflected.
                self._send(200, '{"name":""}', ct="application/json")
        else:
            self._send(404, "<html><body>404 Not Found</body></html>")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
