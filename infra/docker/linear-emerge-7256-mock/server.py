#!/usr/bin/env python3
"""Mock for Linear eMerge E3-Series — CVE-2019-7256 OS command injection.

LINEAR_EMERGE_MODE:
  vuln     — /card_scan.php evaluates `$(...)` in ReaderNo like a real shell
             (inner empty `$()` → "", `echo ARG` → ARG), so a probe's inert
             echo collapses to a contiguous marker in the response.
  patched  — /card_scan.php does not evaluate shell metacharacters (404).
  reflect  — echoes the raw (decoded) ReaderNo verbatim WITHOUT evaluating it
             (adversarial negative: `$(echo ...$()...)` stays intact).
  constant — always returns a fixed "NOCTIS<fixed-hex>" marker regardless of
             input (adversarial negative: never matches the per-run token).
Only `vuln` and `patched` are used by the inventory; `reflect`/`constant`
exist to prove the feed rejects a cheating mock.
"""
import os
import re
from urllib.parse import urlparse, parse_qs, unquote
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

MODE = os.environ.get("LINEAR_EMERGE_MODE", "patched")

# A fixed marker for the "constant" cheating-mock negative control.
CONSTANT_MARKER = "NOCTIS" + ("ab" * 16)

_CMDSUB = re.compile(r"\$\(([^()]*)\)")


def eval_shell(value):
    """Minimal, inert emulation of bash `$(...)` command substitution.

    Only an empty `$()` (→ "") and `echo ARG` (→ ARG) are recognised; any other
    command yields no output. Innermost substitutions collapse first, so
    `$(echo NOCTIS$()abc)` → `$(echo NOCTISabc)` → `NOCTISabc`. Nothing is
    executed on the host — this is pure string rewriting.
    """
    s = value
    for _ in range(16):  # bounded; defeats pathological nesting
        m = _CMDSUB.search(s)
        if not m:
            break
        inner = m.group(1).strip()
        if inner == "":
            out = ""
        elif inner == "echo" or inner.startswith("echo "):
            out = inner[4:].strip()
        else:
            out = ""
        s = s[: m.start()] + out + s[m.end() :]
    return s


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
        parsed = urlparse(self.path)
        if parsed.path != "/card_scan.php":
            self._send(404, "Not found")
            return

        if MODE == "patched":
            # The fixed firmware rejects the request / does not shell out.
            self._send(404, "Not found")
            return

        qs = parse_qs(parsed.query, keep_blank_values=True)
        reader_no = unquote(qs.get("ReaderNo", [""])[0])

        if MODE == "constant":
            # Cheating mock: always emits a fixed marker, ignoring the input.
            self._send(200, "Card scan result: %s\n" % CONSTANT_MARKER)
            return

        if MODE == "reflect":
            # Reflects the decoded input without evaluating the shell.
            self._send(200, "Card scan result: %s\n" % reader_no)
            return

        # MODE == "vuln": the injected command substitution is executed.
        result = eval_shell(reader_no)
        self._send(200, "Card scan result: %s\n" % result)

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
