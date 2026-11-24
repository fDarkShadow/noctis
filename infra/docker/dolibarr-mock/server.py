#!/usr/bin/env python3
"""Dolibarr <= 4.0.4 mock (CVE-2017-7886 / -7887 / -7888 / -8879).

Vuln: /theme/eldy/style.css.php concatenates the raw `lang` parameter into the
translation-override query; a quote in it breaks the SQL and Dolibarr prints the
failing request inside its database error block (HTTP 200).
Patched: `lang` is sanitised, the stylesheet is served normally.
"""
import os, ssl, threading
from urllib.parse import urlsplit, parse_qs
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("DOLIBARR_MODE", "patched") == "vuln"

CSS = "/* Default styles for Dolibarr eldy theme */\nbody { font-family: arial, tahoma, verdana, helvetica; }\n"


def sql_error_page(lang):
    return (
        "<html><head><title>Dolibarr</title></head><body>\n"
        "<div class=\"error\">\n"
        "<b>Error</b><br>\n"
        "<b>Dolibarr has detected a technical error.</b><br>\n"
        "Date: 20170412120000<br>\n"
        "<b>Dolibarr version:</b> 4.0.4<br>\n"
        "<b>Database type manager:</b> mysqli<br>\n"
        "<b>Latest database access request error:</b> SELECT transkey, transvalue FROM llx_overwrite_trans where lang='"
        + lang + "'<br>\n"
        "<b>Return code for latest database access request error:</b> DB_ERROR_SYNTAX<br>\n"
        "<b>Information for latest database access request error:</b> You have an error in your SQL syntax; "
        "check the manual that corresponds to your MySQL server version<br>\n"
        "</div>\n</body></html>\n"
    )


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
        parts = urlsplit(self.path)
        if parts.path in ("/theme/eldy/style.css.php", "/dolibarr/theme/eldy/style.css.php"):
            lang = parse_qs(parts.query).get("lang", ["en_US"])[0]
            if VULN_MODE and "'" in lang:
                self._send(200, sql_error_page(lang), "text/html; charset=UTF-8")
            else:
                self._send(200, CSS, "text/css; charset=UTF-8")
        elif parts.path in ("/", "/index.php"):
            self._send(200, "<html><head><title>Login @ 4.0.4</title></head><body>Dolibarr</body></html>",
                       "text/html; charset=UTF-8")
        else:
            self._send(404, "Not found")

    def do_POST(self): self.do_GET()


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
