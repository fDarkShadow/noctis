#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("JIRA_MODE", "patched") == "vuln"

WEBXML_BODY = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<web-app xmlns="http://java.sun.com/xml/ns/javaee" version="3.0">\n'
    '  <display-name>JIRA</display-name>\n'
    '  <filter><filter-name>security</filter-name></filter>\n'
    '</web-app>\n'
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
        if VULN_MODE and "/_/;" in self.path and "WEB-INF/web.xml" in self.path:
            self._send(200, WEBXML_BODY, "application/xml")
        else:
            self._send(404, "Not found")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
