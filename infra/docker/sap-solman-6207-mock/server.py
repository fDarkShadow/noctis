#!/usr/bin/env python3
# Mock for SAP Solution Manager 7.2 EEM / CA Introscope agent administration
# endpoint (CVE-2020-6207, unauthenticated RCE).
#
# PURE STRING SIMULATION — there is NO subprocess / os.system / exec / eval and
# NO file I/O. The "command execution" is modelled by parsing the echo argument
# out of the SOAP body and stripping the empty command-substitution `$()`, i.e.
# simulating what a real shell would do to the payload. Nothing on the host runs.
#
# Modes (SAP_SOLMAN_MODE):
#   vuln     — missing auth check: the unauthenticated EemAdmin request is
#              accepted and the (collapsed) echo output is returned → detectable.
#   patched  — the authorization check is restored: the same unauthenticated
#              request is rejected (401) and nothing is echoed → clean.
#
# Optional test-only knobs (used by the sandbox negative-case checks, never set
# by the shipped inventory):
#   SAP_SOLMAN_AUTH_REQUIRED=1 — model a present-but-authenticated endpoint:
#              echoes only when an Authorization header is supplied, else 401.
#   SAP_SOLMAN_CONSTANT=1      — model a naive/cheating endpoint that returns a
#              fixed constant marker instead of collapsing the per-run nonce.
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("SAP_SOLMAN_MODE", "patched") == "vuln"
AUTH_REQUIRED = os.environ.get("SAP_SOLMAN_AUTH_REQUIRED") == "1"
CONSTANT_MARKER = os.environ.get("SAP_SOLMAN_CONSTANT") == "1"

EEM_PATH = "/EemAdminService/EemAdmin"

CMD_RE = re.compile(r"<command>(.*?)</command>", re.DOTALL)


def _soap_response(output):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"'
        ' xmlns:adm="http://sap.com/smd/eem/admin/"><soapenv:Body>'
        "<adm:getAllAgentInfoResponse>"
        '<agent product="SAP NetWeaver Application Server">'
        "<commandOutput>" + output + "</commandOutput>"
        "</agent></adm:getAllAgentInfoResponse>"
        "</soapenv:Body></soapenv:Envelope>"
    )


def _simulate_echo(cmd):
    # cmd looks like: echo NOCTIS$()<32-hex-nonce>
    # A real shell strips the empty `$()`, yielding the contiguous stdout.
    cmd = cmd.strip()
    if not cmd.startswith("echo "):
        return ""
    arg = cmd[len("echo "):].strip()
    if CONSTANT_MARKER:
        # Naive/cheating endpoint: ignores the per-run nonce entirely.
        return "NOCTIS" + ("0" * 32)
    return arg.replace("$()", "")


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

    def do_GET(self):
        # Benign landing page so the service looks like a Solution Manager host.
        self._send(200, "SAP Solution Manager Diagnostics", ct="text/html")

    def do_POST(self):
        if self.path != EEM_PATH:
            self._send(404, "Not found")
            return

        if not VULN_MODE:
            # Patched: authorization check enforced on the unauthenticated call.
            self._send(401, "Unauthorized")
            return

        if AUTH_REQUIRED and not self.headers.get("Authorization"):
            # Present endpoint that still enforces auth — unauthenticated denied.
            self._send(401, "Unauthorized")
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        m = CMD_RE.search(body)
        output = _simulate_echo(m.group(1)) if m else ""
        self._send(200, _soap_response(output), ct="text/xml; charset=UTF-8")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
