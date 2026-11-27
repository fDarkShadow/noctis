#!/usr/bin/env python3
# Inert string-simulation of PHPMailer's sender-parameter handling for
# CVE-2016-10033. NO mail() is sent, NO subprocess/exec runs, NOTHING is written
# to disk — the vuln path only *parses* the smuggled sendmail argument the way a
# shell would and echoes the resulting argv back, so the detection feed can
# observe the vulnerable sink without any real exploitation.
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("PHPMAILER_MODE", "patched") == "vuln"

# What PHPMailer >= 5.2.18 enforces on the From address before it is ever used
# to build the sendmail argument list. The smuggled injection is not RFC-valid.
ADDR_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def shell_parse_args(raw):
    """Minimal simulation of the shell word-splitting + quote removal the
    *vulnerable* PHPMailer path exposes the From address to: PHP mail() runs
    `sh -c 'sendmail ... -f<Sender>'`, so empty quoted strings ("") collapse and
    quote characters are stripped, turning smuggled -X/-O options into real argv
    tokens. No command is executed and nothing touches the filesystem."""
    stripped = raw.replace('"', "")          # quote removal: "" vanishes, joining neighbours
    return [tok for tok in stripped.split() if tok]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ct="text/plain", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _email_field(self, body):
        # email is the last form field, so take everything after it to end of
        # body (its value legitimately contains '=' from -OQueueDirectory).
        i = body.find("email=")
        return None if i < 0 else body[i + len("email="):]

    def do_GET(self):
        # Plain contact page — never surfaces the marker.
        self._send(200, "PHPMailer contact form")

    def do_POST(self):
        if self.path != "/contact.php":
            self._send(404, "Not found")
            return
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(n).decode("utf-8", errors="replace")
        email = self._email_field(body)
        if email is None:
            self._send(400, "missing email field")
            return

        if not VULN_MODE:
            # Patched: validate the address first. The smuggled From is rejected
            # before sendmail arguments are built, so no marker is ever surfaced
            # and no "mail sent" 302 is returned.
            if ADDR_RE.match(email.strip()):
                self._send(302, "", extra={"Location": "/thanks"})
            else:
                self._send(200, "Invalid email address")
            return

        # Vulnerable: raw From becomes Sender -> `-f<Sender>` -> mail() -> shell.
        # Parse the argv the shell would produce and surface the -X/-O options.
        argv = shell_parse_args("/usr/sbin/sendmail -t -i -f" + email)
        xarg = next((a for a in argv if a.startswith("-X")), "")
        oarg = next((a for a in argv if a.startswith("-OQueueDirectory")), "")
        dbg = "NOCTIS_PHPMAILER_CONFIRMED mail queued; sendmail argv: %s %s" % (oarg, xarg)
        self._send(302, dbg, extra={"Location": "/thanks"})


if __name__ == "__main__":
    serve(Handler, HTTPServer)
