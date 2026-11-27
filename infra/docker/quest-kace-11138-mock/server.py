#!/usr/bin/env python3
"""Mock Quest KACE SMA (K1000) — CVE-2018-11138 pre-auth OS command injection.

The vulnerable endpoint /common/download_agent_installer.php concatenates the
`orgid` GET parameter into a shell command run as the web server user. This
mock simulates that behaviour with PURE string/regex operations only — it never
runs a real command, touches the filesystem, or makes a network callback.

Vuln mode: when `orgid` carries a `;<cmd>` injection, the mock emulates a POSIX
shell just far enough to prove the collapse primitive: it evaluates an `echo`
argument, performing empty-command-substitution collapse ($() -> "") exactly as
a real shell would, then reflects the resulting output. So `echo NOCTIS$()<tok>`
yields the contiguous string NOCTIS<tok>.

Patched mode: the endpoint ignores/sanitises `orgid` and returns the ordinary
agent-installer stub — no reflection, so no detection branch fires.

Deliberately realistic against adversarial review:
  * patched                    -> never reflects      -> 0 findings
  * verbatim-echo (no collapse)-> leaves $() in place -> regex/gate fail
  * constant marker            -> fixed hex != per-run -> stridx gate fails
  * benign orgid (no `;echo`)  -> no command executed  -> 0 findings
"""
import os
import re
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("KACE_MODE", "patched") == "vuln"
KACE_VERSION = "8.0.318" if VULN_MODE else "9.0.146"

# How a stricter attacker-side reviewer may flip this one mock into a "cheating"
# variant purely via env, to prove the feed rejects each shortcut. Default off:
# the real vuln mock emulates the shell faithfully.
CHEAT = os.environ.get("KACE_CHEAT", "")  # "" | "verbatim" | "constant"


def shell_expand(word):
    """Emulate POSIX word expansion for the pieces this check uses.

    Only command substitution matters here: `$(...)` runs the inner command and
    is replaced by its stdout. We never execute anything, so an empty `$()`
    expands to the empty string (correct) and any non-empty substitution also
    expands to empty (inert — we refuse to run real commands). This collapse is
    the exact behaviour that makes NOCTIS$()<tok> come back as NOCTIS<tok>.
    """
    return re.sub(r"\$\([^)]*\)", "", word)


def run_echo(cmd):
    """Simulate `echo <args>` on the injected command; return its stdout."""
    cmd = cmd.strip()
    if not cmd.startswith("echo"):
        return None
    arg = cmd[len("echo"):].strip()
    return shell_expand(arg)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Kace-Appliance", "K1000")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)
        orgid = params.get("orgid", [""])[0]

        if path == "/common/download_agent_installer.php":
            if not VULN_MODE:
                # Patched: orgid is validated/ignored; plain installer stub.
                self._send(
                    200,
                    "KACE Agent Installer\n"
                    "<?build=9.0.146 ?>\nquest kace sma\n",
                    "text/html",
                )
                return

            # Vulnerable: orgid is spliced into a shell command. Split on the
            # first `;` to recover the injected command, then emulate the shell.
            injected = None
            if ";" in orgid:
                injected = orgid.split(";", 1)[1]

            output = None
            if injected is not None:
                out = run_echo(injected)
                if out is not None:
                    if CHEAT == "verbatim":
                        # Cheating variant: echo the argument WITHOUT collapsing
                        # $(); leaves NOCTIS$()<tok> → feed must reject it.
                        arg = injected.strip()[len("echo"):].strip()
                        output = arg
                    elif CHEAT == "constant":
                        # Cheating variant: reflect a fixed, non-per-run marker.
                        output = "NOCTIS" + ("0" * 32)
                    else:
                        output = out

            body = (
                "KACE Agent Installer\n"
                "<?build=8.0.318 ?>\nquest kace sma\n"
            )
            if output is not None:
                # The command's stdout lands in the generated page, as it would
                # when the appliance shells out to build the installer.
                body += "agent-org: " + output + "\n"
            self._send(200, body, "text/html")
            return

        if path == "/":
            self._send(200, "<html><title>KACE SMA</title><body>K1000</body></html>", "text/html")
            return

        self._send(404, "Not found")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
