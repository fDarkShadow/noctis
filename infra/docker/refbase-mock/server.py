#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("REFBASE_MODE", "patched") == "vuln"

# The injected marker carried in the UNION payload.
MARKER = "SQL-INJECTION-TEST"
# Server-computed strings that CANNOT appear in a URL reflection: the forced
# MySQL error text immediately followed by the @@version digits, plus the
# refbase product string. These are what the feed actually matches on.
DB_VERSION = "5.5.40"


class Handler(BaseHTTPRequestHandler):
    # Respond as HTTP/1.1 so the status line matches the NASL's "HTTP/1.1 302".
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html", extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = self.path
        pl = p.lower()

        # rss.php — the injectable 'where' parameter. A vulnerable refbase only
        # redirects when the real UNION/concat injection (with the marker and
        # the forced-error string) is present, not for arbitrary requests.
        if p.startswith("/rss.php"):
            injected = (
                VULN_MODE
                and "where=" in pl
                and "union" in pl
                and "concat(" in pl
                and MARKER in p
                and "error%20in%20your%20sql%20syntax" in pl
            )
            if injected:
                # 302 to show.php. Location is relative (no leading slash),
                # matching the NASL eregmatch char-class and real refbase.
                self._send(
                    302,
                    "",
                    ct="text/xml",
                    extra_headers=[("Location", "show.php?record=%s" % MARKER)],
                )
            else:
                # Patched / benign: a normal RSS feed, no redirect, no marker.
                self._send(
                    200,
                    "<?xml version=\"1.0\"?>\n"
                    "<rss version=\"2.0\"><channel>"
                    "<title>refbase RSS</title>"
                    "<description>Reference database feed</description>"
                    "</channel></rss>",
                    ct="text/xml",
                )
            return

        # show.php — the redirect target. In vuln mode it surfaces the raw MySQL
        # error (server-computed: the error text + @@version digits), the
        # refbase product string, and the reflected marker. This is the page the
        # feed follows and matches; a patched refbase renders a benign record.
        if p.startswith("/show.php"):
            if VULN_MODE and MARKER in p:
                self._send(
                    200,
                    "<html><head><title>refbase -- record</title></head><body>"
                    "<div class=\"refbase\">Powered by refbase</div>"
                    "<p>version:You have an error in your sql syntax%s'%s'</p>"
                    "</body></html>" % (DB_VERSION, MARKER),
                )
            else:
                self._send(
                    200,
                    "<html><head><title>refbase -- record</title></head><body>"
                    "<div class=\"refbase\">Powered by refbase</div>"
                    "<p>Record not found.</p></body></html>",
                )
            return

        self._send(404, "<html><body>404 Not Found</body></html>")

    def do_POST(self):
        self.do_GET()


def _make_https_server(port):
    certdir = os.environ.get("CERT_DIR", "/certs")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certdir + "/server.crt", certdir + "/server.key")
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    https = _make_https_server(443)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
