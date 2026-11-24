#!/usr/bin/env python3
"""Mock VMware Spring Cloud Function — CVE-2022-22963 SpEL injection RCE.

Vuln mode: a POST /functionRouter carrying a
`spring.cloud.function.routing-expression` header has that header "evaluated"
as SpEL — the mock surfaces a SpelEvaluationException marker (response
differential) and, if the expression runs `curl <url>`, performs the callback
(the emulated RCE) to that URL.

Patched mode: the routing-expression header is ignored (no evaluation, no
marker, no callback).
"""
import os
import re
import ssl
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("SPRING_MODE", "patched") == "vuln"

ROUTING_HEADER = "spring.cloud.function.routing-expression"
URL_RE = re.compile(r"https?://[^\s\"'})]+")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)

        expr = self.headers.get(ROUTING_HEADER)
        if path == "/functionRouter" and VULN_MODE and expr:
            # The payload is "evaluated": if it runs curl <url>, fire the callback.
            if "exec(" in expr and "curl" in expr:
                m = URL_RE.search(expr)
                if m:
                    try:
                        urllib.request.urlopen(m.group(0), timeout=5).read()
                    except Exception:
                        pass
            # Surface the SpEL evaluation exception (real vulnerable servers do).
            self._send(
                500,
                "org.springframework.expression.spel.SpelEvaluationException: "
                "EL1004E: Method call failed — NOCTIS_SPRING_SPEL_EVALUATED",
            )
            return

        if path == "/functionRouter":
            # Patched: header ignored; normal (empty) function routing.
            self._send(200, "")
            return

        self._send(404, "Not Found")

    def do_GET(self):
        if self.path.split("?", 1)[0] == "/":
            self._send(200, "Whitelabel Error Page (Spring)", "text/html")
            return
        self._send(404, "Not Found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
