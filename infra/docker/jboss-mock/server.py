#!/usr/bin/env python3
# Inert mock for CVE-2017-12149 (JBoss HTTPInvoker ReadOnlyAccessFilter exposure).
#
# Vuln mode simulates an unsecured JBoss AS: the HTTPInvoker endpoints
# (/invoker/readonly and /invoker/JMXInvokerServlet) are reachable unauthenticated
# and answer even a benign GET by advertising the Java invocation stream via
# Content-Type: application/x-java-serialized-object. No real serialized object and
# no deserialization are involved — the body is a plain-text placeholder. Every
# other path returns ordinary web content, so a non-invoker control request never
# carries the serialized-object signature.
#
# Patched mode simulates a server with the invoker war undeployed / ReadOnlyAccessFilter
# removed: the invoker endpoints return 404 text/html, so the detection differential fails.
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("JBOSS_MODE", "patched") == "vuln"

INVOKER_PATHS = ("/invoker/readonly", "/invoker/JMXInvokerServlet")

# Inert placeholder standing in for the JBoss MarshalledInvocation response. It is a
# plain string, NOT a real serialized Java object (no serialization magic bytes).
INVOKER_STREAM = "NOCTIS_JBOSS_CONFIRMED jboss-http-invoker MarshalledInvocation (inert placeholder)"

HOME_PAGE = (
    "<html><head><title>Welcome to JBoss AS</title></head>"
    "<body><h1>Welcome to JBoss</h1><p>JBoss Application Server</p></body></html>"
)


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

    def _path(self):
        return self.path.split("?", 1)[0].rstrip("/") or "/"

    def do_GET(self):
        path = self._path()
        if path in INVOKER_PATHS:
            if VULN_MODE:
                # Unsecured invoker: reachable unauthenticated, answers with the
                # invocation stream content type.
                self._send(200, INVOKER_STREAM, ct="application/x-java-serialized-object")
            else:
                # Patched: invoker undeployed / filtered.
                self._send(404, "<html><body>Not Found</body></html>", ct="text/html")
        elif path == "/":
            self._send(200, HOME_PAGE, ct="text/html")
        else:
            self._send(404, "<html><body>Not Found</body></html>", ct="text/html")

    def do_POST(self):
        # The feed never POSTs a gadget; mirror GET behaviour for completeness.
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
