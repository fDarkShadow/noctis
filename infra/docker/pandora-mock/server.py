#!/usr/bin/env python3
# Mock for Pandora FMS < 5.1 SP1 mobile-console pre-auth SQL injection
# (CVE-2014-125115), ported from 2014/gb_pandora_fms_mult_vuln_dec14.nasl.
#
# Both modes serve a realistic Pandora FMS mobile console:
#   GET  /mobile/index.php  → the login form with the dynamic input<token>
#                             hidden field (same markup in vuln and patched).
# The difference is only in how the login POST handles the injection:
#   vuln mode:    user beginning with a single quote (%27) breaks the SQL
#                 query and the backend reflects the injected marker inside a
#                 ">SQL error<" message on the mobile console page.
#   patched mode: the same request is sanitised — the console re-renders the
#                 login form with an "invalid credentials" notice, no SQL error,
#                 so the feed does not fire (meaningful true negative).
#
# A login POST WITHOUT the single-quote injection never produces the SQL error
# in either mode, so the true positive proves the payload matters.
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("PANDORA_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

# Dynamic hidden field name the mobile login form renders. The feed extracts
# the token via eregmatch("input([0-9a-z]+).*id", ...); the field name and the
# following id= attribute are kept on one line so the (newline-less) regex
# matches. A fixed value keeps the stateless mock's GET and POST in agreement.
LOGIN_TOKEN = "3fa2b9c7"

# Mobile console login form (served on GET in both modes).
LOGIN_FORM = (
    "<!DOCTYPE html>\n"
    "<html><head><title>Pandora FMS mobile</title></head>\n"
    "<body data-role=\"page\" class=\"ui-page\">\n"
    "<div data-role=\"content\">\n"
    "<form action=\"index.php\" method=\"post\" data-ajax=\"false\">\n"
    "<input type=\"hidden\" name=\"action\" value=\"login\">\n"
    "<input type=\"hidden\" name=\"input{tok}\" id=\"hidden-login-token\" value=\"1\">\n"
    "<label for=\"user\">User</label>\n"
    "<input type=\"text\" name=\"user\" id=\"user\">\n"
    "<label for=\"password\">Password</label>\n"
    "<input type=\"password\" name=\"password\" id=\"password\">\n"
    "<button type=\"submit\" name=\"input{tok}\" value=\"Login\">Login</button>\n"
    "</form></div></body></html>\n"
).format(tok=LOGIN_TOKEN)

# Vulnerable login response: the injected marker is reflected inside a SQL error
# on one line so ">SQL error<.*SQL-Injection-Test" matches. The ">Pandora FMS
# mobile<" fingerprint is present so the feed's condition is satisfied.
SQLI_ERROR_PAGE = (
    "<!DOCTYPE html>\n"
    "<html><head><title>Pandora FMS mobile</title></head>\n"
    "<body data-role=\"page\">\n"
    "<div data-role=\"content\"><h2>SQL error</h2> "
    "You have an error in your SQL syntax; check the manual that corresponds to "
    "your MySQL server version for the right syntax to use near "
    "'''SQL-Injection-Test' AND pass = ... ' at line 1</div>\n"
    "</body></html>\n"
)

# Benign "invalid login" response: real console, same fingerprint, no SQL error.
INVALID_LOGIN_PAGE = (
    "<!DOCTYPE html>\n"
    "<html><head><title>Pandora FMS mobile</title></head>\n"
    "<body data-role=\"page\">\n"
    "<div data-role=\"content\"><p class=\"login_nok\">Invalid credentials. "
    "Please try again.</p></div>\n"
    "</body></html>\n"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, body, ct="text/html", extra_headers=None):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items(): self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/mobile/index.php":
            self._send(200, LOGIN_FORM)
        else:
            self._send(404, "Not found")

    def do_POST(self):
        if self.path != "/mobile/index.php":
            self._send(404, "Not found")
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        # The injection: user parameter starting with a single quote (%27 / ').
        injected = ("user=%27" in body) or ("user='" in body)
        if VULN_MODE and injected:
            self._send(200, SQLI_ERROR_PAGE)
        else:
            # Patched (sanitised) or a benign login attempt: no SQL error.
            self._send(200, INVALID_LOGIN_PAGE)


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(CERT_DIR, "server.crt"), os.path.join(CERT_DIR, "server.key"))
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    if PORT_HTTPS:
        threading.Thread(target=lambda: _make_https_server(PORT_HTTPS).serve_forever(), daemon=True).start()
    if PORT_HTTP:
        HTTPServer(("0.0.0.0", PORT_HTTP), Handler).serve_forever()
    else:
        threading.Event().wait()
