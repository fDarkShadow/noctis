#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote

VULN_MODE = os.environ.get("KLOXO_MODE", "patched") == "vuln"

# Precondition marker — served by EVERY Kloxo (patched or not) on the
# webcommand.php endpoint. The NASL uses it only to confirm the endpoint exists.
PRECONDITION = "__error_only_clients_and_auxiliary_allowed_to_login"
# Server-computed marker emitted only when the injected UNION SELECT actually
# executes (login proceeds past the SQL stage). This is NOT present in the URL.
LOGIN_ERROR = "_error_login_error"


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

    def _is_real_injection(self):
        # Decode the request and require the genuine NASL login-name payload:
        # a UNION SELECT reading the `realpass` column from `client`. A bare
        # request to the endpoint must NOT trip this (not self-fulfilling).
        decoded = unquote(self.path).lower()
        return ("login-name=" in decoded
                and "union select" in decoded
                and "realpass" in decoded
                and "from client" in decoded)

    def do_GET(self):
        # Kloxo command endpoint — present on every Kloxo install.
        if self.path.startswith("/lbin/webcommand.php"):
            if self._is_real_injection():
                # The injected SQL executes: a vulnerable Kloxo proceeds past
                # the SQL stage to the login/password check and emits the
                # login-error marker. A patched Kloxo sanitises the input and
                # just re-serves the normal "clients only" screen.
                if VULN_MODE:
                    self._send(200,
                        "<html><body>"
                        "<error>%s</error>"
                        "</body></html>" % LOGIN_ERROR)
                else:
                    self._send(200,
                        "<html><body>"
                        "<error>%s</error>"
                        "</body></html>" % PRECONDITION)
            else:
                # Bare request / endpoint confirmation — served identically in
                # both modes so the precondition gate passes on vuln AND patched.
                self._send(200,
                    "<html><body>"
                    "<error>%s</error>"
                    "</body></html>" % PRECONDITION)
        else:
            self._send(404, "<html><body>404 Not Found</body></html>")

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
