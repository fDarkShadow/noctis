#!/usr/bin/env python3
"""Mock ManageEngine Desktop Central — CVE-2018-5337/5338/5339/5341.

Vuln mode: /jsp/admin/DBQueryExecutor.jsp is reachable without authentication;
actionFrom=getResult with a SELECT query returns the Query Executor page plus a
result table for the aaauser table. Patched mode: the page is not served
without an authenticated session (404).
"""
import os
import ssl
import threading
from urllib.parse import urlsplit, parse_qs
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("MANAGEENGINE_MODE", "patched") == "vuln"

PAGE_HEAD = """<html><head><title>Query Executor</title></head><body>
<h3>Query Executor</h3>
<p>This tool is used to execute SQL queries against the Desktop Central database
in order to retrieve any specific  information required for troubleshooting.</p>
<form action="/jsp/admin/DBQueryExecutor.jsp" method="get">
<input type="hidden" name="actionFrom" value="getResult"/>
<textarea name="query"></textarea><input type="submit" value="Execute"/>
</form>
"""

RESULT_TABLE = """<table border="1">
<tr><th>USER_ID</th><th>FIRST_NAME</th><th>MIDDLE_NAME</th><th>LAST_NAME</th><th>DISPLAY_NAME</th><th>CREATEDTIME</th></tr>
<tr><td>1</td><td>admin</td><td></td><td></td><td>admin</td><td>1514764800000</td></tr>
<tr><td>2</td><td>guest</td><td></td><td></td><td>guest</td><td>1514764800000</td></tr>
</table>
"""


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
        parts = urlsplit(self.path)
        qs = parse_qs(parts.query)
        if VULN_MODE and parts.path == "/jsp/admin/DBQueryExecutor.jsp":
            body = PAGE_HEAD
            query = qs.get("query", [""])[0].strip().lower()
            if qs.get("actionFrom", [""])[0] == "getResult" and query.startswith("select") \
                    and "aaauser" in query:
                body += RESULT_TABLE
            self._send(200, body + "</body></html>")
        elif parts.path in ("/", "/configurations.do"):
            self._send(200, "<html><head><title>ManageEngine Desktop Central</title></head>"
                            "<body>Login</body></html>")
        else:
            self._send(404, "<html><body>Not Found</body></html>")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
