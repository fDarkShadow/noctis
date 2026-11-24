#!/usr/bin/env python3
"""Mock CUPS web interface — CVE-2015-1158 / CVE-2015-1159.

Vuln mode: the /help/ page reflects the QUERY request parameter into the HTML
response unescaped (CVE-2015-1159 reflected XSS). Patched mode (CUPS >= 2.0.3):
the same page HTML-escapes the QUERY value, so the injected <script> tag never
appears verbatim and no finding is produced.

The feed probes with a verbatim HTTP/1.0 request whose path keeps the %xx
encoding, so the handler decodes self.path itself rather than trusting a
normalised path.
"""
import html
import os
import ssl
import threading
from urllib.parse import urlsplit, parse_qs, unquote
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("CUPS_MODE", "patched") == "vuln"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "CUPS/1.7 IPP/2.1")
        self.end_headers()
        self.wfile.write(body)

    def _help_page(self, reflected):
        return (
            "<!DOCTYPE html>\n<html>\n<head>\n"
            "<title>Online Help - CUPS 1.7.2</title>\n</head>\n<body>\n"
            "<h1><a href=\"/help/\">Online Help</a></h1>\n"
            "<form action=\"/help/\" method=\"GET\">\n"
            "<input type=\"text\" name=\"QUERY\" value=\"" + reflected + "\">\n"
            "<input type=\"submit\" name=\"SEARCH\" value=\"Search\">\n"
            "</form>\n"
            "<p>Search results for " + reflected + "</p>\n"
            "<p>CUPS is the standards-based, open source printing system.</p>\n"
            "</body>\n</html>\n"
        )

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path == "/help/" or parts.path == "/help":
            query = parse_qs(parts.query, keep_blank_values=True).get("QUERY", [""])[0]
            # parse_qs already percent-decodes; unquote() again is a no-op guard.
            query = unquote(query)
            if VULN_MODE:
                # Vulnerable: user input echoed into the page without escaping.
                self._send(200, self._help_page(query))
            else:
                # Patched (CUPS >= 2.0.3): the templating engine escapes input.
                self._send(200, self._help_page(html.escape(query, quote=True)))
            return
        self._send(404, "Not Found")

    def do_POST(self):
        self.do_GET()


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
