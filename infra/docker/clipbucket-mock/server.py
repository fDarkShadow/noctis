#!/usr/bin/env python3
"""ClipBucket mock — two independent SQL-injection endpoints:

* videos.php `time` parameter  (CVE-2012-6642 / CVE-2012-6643 / CVE-2012-6644)
  vuln:    a quote in `time` breaks the SQL query -> 200 + MySQL syntax error
           echoing the injected value.
  patched: the parameter is sanitised -> normal video listing, no SQL error.

* view_page.php `pid` parameter (CVE-2012-5849)
  vuln:    the injected UNION SELECT concat() column reflects the marker into
           the page (only when the real hex literal is present in the request).
  patched: normal ClipBucket page, no marker.
"""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs
from mocklib import serve

VULN_MODE = os.environ.get("CLIPBUCKET_MODE", "patched") == "vuln"

LISTING = (
    "<html><head><title>Videos - ClipBucket</title></head><body>"
    "<h1>Videos</h1><div class='videos'>No videos found</div>"
    "<p>ClipBucket Copyright &copy; 2007 - 2012</p></body></html>"
)

# Marker reflected by the injected UNION SELECT concat() column (CVE-2012-5849),
# per the OpenVAS plugin. Hex 0x53514c2d496e6a656374696f6e2d54657374 decodes to
# "SQL-Injection-Test"; reflected ONLY when that literal is sent (not self-fulfilling).
MARKER = "SQL-Injection-Test"
MARKER_HEX = "53514c2d496e6a656374696f6e2d54657374"

# ClipBucket fingerprint — served in both modes (NASL extra_check ">ClipBucket").
BRAND = ">ClipBucket"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = urlsplit(self.path)
        path = parts.path
        # view_page.php — CVE-2012-5849, injectable pid parameter (UNION marker).
        if path.startswith("/view_page.php"):
            p = self.path
            if VULN_MODE and MARKER_HEX in p.lower():
                # Vulnerable: the concat() column reflects the marker into the page.
                self._send(200,
                    "<html><head><title>ClipBucket</title></head><body>"
                    "<h1%s</h1>"
                    "<div class='page-title'>%s<br/></div>"
                    "<a href='login.php'>Login</a></body></html>" % (BRAND, MARKER))
            else:
                # Patched, or benign/incomplete request: normal ClipBucket page.
                self._send(200,
                    "<html><head><title>ClipBucket</title></head><body>"
                    "<h1%s</h1>"
                    "<p>Page not available.</p>"
                    "<a href='login.php'>Login</a></body></html>" % BRAND)
        # videos.php — CVE-2012-6642/6643/6644, time parameter SQL error.
        elif path in ("/videos.php", "/clipbucket/videos.php"):
            time_v = parse_qs(parts.query, keep_blank_values=True).get("time", [""])[0]
            if VULN_MODE and "'" in time_v:
                body = (
                    "<html><body><b>Database error:</b> You have an error in your SQL syntax; "
                    "check the manual that corresponds to your MySQL server version for the "
                    "right syntax to use near '" + time_v.split("'", 1)[1] +
                    "' ORDER BY date_added DESC LIMIT 0,20' at line 1</body></html>"
                )
                self._send(200, body)
            else:
                self._send(200, LISTING)
        else:
            self._send(404, "Not found", "text/plain")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
