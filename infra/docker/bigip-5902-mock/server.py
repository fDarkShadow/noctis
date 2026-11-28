#!/usr/bin/env python3
"""Mock F5 BIG-IP TMUI — CVE-2020-5902 (TMUI unauthenticated RCE).

The real bug: TMUI's `/tmui/login.jsp/..;/` path-traversal lets an
unauthenticated attacker reach internal JSP endpoints. The documented RCE chain
(exphub / Metasploit) is:

    1. tmshCmd.jsp?command=create cli alias private list command bash   (alias `list` -> bash)
    2. fileSave.jsp?fileName=<f>&content=<payload>                      (write a script file)
    3. tmshCmd.jsp?command=list <f>                                     (`list` now runs bash <f>)

Step 3 executes attacker-controlled content. This mock faithfully *reflects*
whatever the probe asked `echo` to print — the matched token therefore appears
only because the injected command "ran", never because the mock hardcoded it.

Vuln mode   : the `..;/` traversal reaches the JSP endpoints and the alias/exec
              chain works, echoing back the probe's own `echo` argument.
Patched mode : the `..;/` traversal is rejected (403), so every step fails.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs, unquote_plus
from mocklib import serve

VULN_MODE = os.environ.get("BIGIP_MODE", "patched") == "vuln"

# Process-wide state (HTTP/1.0 probes arrive on separate connections).
STATE = {"alias": False, "files": {}}

# The real TMUI traversal prefix that bypasses authentication.
TRAVERSAL = "/tmui/login.jsp/..;/"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html;charset=UTF-8"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "BIG-IP")
        self.end_headers()
        self.wfile.write(body)

    def _handle(self):
        split = urlsplit(self.path)
        path = split.path
        qs = parse_qs(split.query, keep_blank_values=True)

        # Only the `/tmui/login.jsp/..;/` traversal reaches the internal JSPs.
        if TRAVERSAL not in self.path:
            self._send(404, "Not Found")
            return

        # A patched BIG-IP rejects the traversal outright.
        if not VULN_MODE:
            self._send(403, "<html><body>Forbidden</body></html>")
            return

        if path.endswith("/tmui/locallb/workspace/tmshCmd.jsp"):
            command = unquote_plus((qs.get("command") or [""])[0])
            # 1) alias creation: `create cli alias private list command bash`
            if command.startswith("create cli alias private list command bash"):
                STATE["alias"] = True
                self._send(200, "")
                return
            # 3) `list <file>` — with the alias in place this runs `bash <file>`.
            if command.startswith("list ") and STATE["alias"]:
                fname = command[len("list "):].strip()
                content = STATE["files"].get(fname, "")
                self._send(200, _run(content))
                return
            self._send(200, "")
            return

        if path.endswith("/tmui/locallb/workspace/fileSave.jsp"):
            fname = unquote_plus((qs.get("fileName") or [""])[0])
            content = unquote_plus((qs.get("content") or [""])[0])
            STATE["files"][fname] = content
            self._send(200, "")
            return

        self._send(404, "Not Found")

    do_GET = _handle
    do_POST = _handle


def _run(content):
    """Simulate `bash <file>`: we only emulate `echo`, so whatever the probe
    asked to echo is reflected verbatim. This mirrors real command execution —
    the output is the attacker's own input, never a string the mock invented.
    A NOCTIS marker is appended only as an extra operator breadcrumb."""
    out = ""
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("echo "):
            out += line[len("echo "):].strip() + "\n"
    return out + "NOCTIS_BIGIP_CONFIRMED\n"


if __name__ == "__main__":
    serve(Handler, HTTPServer)
