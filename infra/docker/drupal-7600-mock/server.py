#!/usr/bin/env python3
"""Drupalgeddon2 (CVE-2018-7600) mock.

Vuln mode faithfully reproduces the Form API property-injection RCE: the
``/user/register`` AJAX endpoint is abused so that a ``#post_render`` callback
(passthru/exec/system) executes the attacker-supplied ``#markup`` command and
its stdout is reflected in the Drupal AJAX JSON response. The mock does not run
a real shell; it emulates the single safe command the feed sends (``echo
<marker>``) by reflecting exactly the argument the attacker passed. Because the
reflected value is request-derived, a match proves the injection path executed
the attacker's command rather than a static banner.

Patched mode rejects the malformed renderable array (HTTP 200 with a normal,
non-reflecting AJAX response), so every detection step fails.
"""
import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

from mocklib import serve

VULN_MODE = os.environ.get("DRUPAL_MODE", "patched") == "vuln"


def _emulate_command(cmd):
    """Emulate the one command class the feed sends: `echo <text>`.

    Returns the stdout a real shell would produce, or None if the command is
    not something this mock knows how to run (a real target would still run it).
    """
    cmd = cmd.strip()
    if cmd.startswith("echo "):
        return cmd[len("echo "):].strip()
    return None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            self._send(200, "<html><head><meta name=\"Generator\" content=\"Drupal 8\" /></head><body>Drupal</body></html>", ct="text/html")
        else:
            self._send(404, '{"message":"Not Found"}')

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        body_raw = self._read_body().decode("utf-8", "replace")

        # The Drupalgeddon2 request targets the user/register AJAX form with the
        # renderable-array injection in the element_parents query parameter.
        is_dg2_request = (
            parsed.path == "/user/register"
            and "element_parents" in qs
            and qs.get("_wrapper_format", [""])[0] == "drupal_ajax"
        )

        if not is_dg2_request:
            self._send(404, '{"message":"Not Found"}')
            return

        # Parse the form-urlencoded body (Drupal percent-decodes the #-prefixed
        # property keys, e.g. mail%5B%23post_render%5D%5B%5D=passthru).
        fields = urllib.parse.parse_qs(body_raw, keep_blank_values=True)
        post_render = fields.get("mail[#post_render][]", [""])[0]
        markup = fields.get("mail[#markup]", [""])[0]

        has_injection = bool(post_render) and bool(markup)

        if VULN_MODE and has_injection:
            # The injected #post_render callback (passthru/system/exec) executes
            # the #markup command; its stdout is reflected in the AJAX response.
            output = _emulate_command(markup)
            if output is None:
                output = ""
            ajax = [
                {
                    "command": "insert",
                    "method": "replaceWith",
                    "data": output + "\n",
                }
            ]
            self._send(200, json.dumps(ajax))
        else:
            # Patched: Drupal sanitises the renderable array; the callback never
            # fires, so a normal (non-reflecting) AJAX envelope is returned.
            ajax = [{"command": "insert", "method": "replaceWith", "data": ""}]
            self._send(200, json.dumps(ajax))


if __name__ == "__main__":
    serve(Handler, HTTPServer)
