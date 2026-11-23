#!/usr/bin/env python3
"""Mock Kibana — CVE-2019-7609 Timelion prototype-pollution RCE.

Vuln mode: a POST /api/timelion/run whose sheet contains a prototype-pollution
`__proto__.env` + `child_process` payload "executes" the embedded command. The
mock parses the marker and the favicons token out of the payload and stores
them, then serves the marker back at /ui/favicons/<token>.txt — emulating the
file the spawned Node child process writes.

Patched mode: the pollution is rejected (400) and nothing is ever stored, so
the favicons path always returns 404.
"""
import os
import re
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("KIBANA_MODE", "patched") == "vuln"

# token -> marker written by the "executed" command (persisted for the scan).
STATE = {}

TOKEN_RE = re.compile(r"favicons/([0-9A-Za-z-]+)\.txt")
MARKER_RE = re.compile(r"(noctis_kibana_rce_[0-9A-Za-z-]+)")

ROOT_BODY = (
    '<!DOCTYPE html><title>Kibana</title>'
    '<div class="kibanaWelcomeView">Loading Kibana</div>'
    '<!-- kbn-version: 6.6.0 -->'
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
        self.send_header("kbn-name", "kibana")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""

        if path == "/api/timelion/run":
            is_pollution = "__proto__" in body and "child_process" in body
            if VULN_MODE and is_pollution:
                # "Execute" the payload: capture token + marker it would write.
                tok = TOKEN_RE.search(body)
                mark = MARKER_RE.search(body)
                if tok and mark:
                    STATE[tok.group(1)] = mark.group(1)
                self._send(
                    200,
                    '{"sheet":[{"list":[{"label":"","data":[]}]}],"stats":{}}',
                    "application/json",
                )
            else:
                # Patched Kibana rejects the malformed/pollution sheet.
                self._send(
                    400,
                    '{"statusCode":400,"error":"Bad Request",'
                    '"message":"Timelion request validation failed"}',
                    "application/json",
                )
            return

        self._send(404, '{"statusCode":404,"error":"Not Found"}', "application/json")

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path.startswith("/socket.io/"):
            self._send(200, "0{\"sid\":\"noctis\"}")
            return

        if path.startswith("/ui/favicons/") and path.endswith(".txt"):
            token = path[len("/ui/favicons/"):-len(".txt")]
            if VULN_MODE and token in STATE:
                self._send(200, STATE[token] + "\n")
            else:
                self._send(404, "Not Found")
            return

        if path == "/":
            self._send(200, ROOT_BODY, "text/html")
            return

        self._send(404, "Not Found")


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
