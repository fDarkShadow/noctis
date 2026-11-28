#!/usr/bin/env python3
# Mock for ThinkPHP 5.0.x invokefunction RCE — CVE-2018-20062.
#
# VULN mode faithfully emulates the vulnerable route: the request
#   /index.php?s=index/think\app/invokefunction
#       &function=call_user_func_array&vars[0]=<fn>&vars[1][]=<arg>
# reaches \think\App::invokefunction, which really calls the chosen PHP function
# on the chosen argument and echoes its return value. We implement exactly that
# for the inert built-in `md5`: the server computes md5(arg) itself and returns
# the digest. Because the probe's token is random per run, this is genuine
# server-side execution, not a canned marker — a mock that reflected a constant
# string could never satisfy the scanner's per-run digest check.
#
# PATCHED mode validates the controller name and never routes into
# invokefunction: the endpoint returns a benign 404, so the digest never appears.
import os
import hashlib
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("THINKPHP_MODE", "patched") == "vuln"

# Functions this mock is willing to "execute" — kept to pure, inert builtins.
SAFE_FUNCS = {
    "md5": lambda a: hashlib.md5(a.encode()).hexdigest(),
    "sha1": lambda a: hashlib.sha1(a.encode()).hexdigest(),
}


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

    def _invoke(self):
        """Return the digest string if the request is the invokefunction
        injection against a known builtin, else None."""
        q = parse_qs(urlparse(self.path).query)
        s = (q.get("s") or [""])[0]
        function = (q.get("function") or [""])[0]
        if "invokefunction" not in s or function != "call_user_func_array":
            return None
        callback = (q.get("vars[0]") or [""])[0]
        args = q.get("vars[1][]") or []
        if callback not in SAFE_FUNCS or not args:
            return None
        return SAFE_FUNCS[callback](args[0])

    def do_GET(self):
        if VULN_MODE:
            digest = self._invoke()
            if digest is not None:
                # ThinkPHP echoes the function's return value verbatim.
                self._send(200, digest, ct="text/html")
                return
            # Unexploited request against the vulnerable app: normal landing page.
            self._send(200, "<html><body>ThinkPHP</body></html>")
            return
        # Patched: controller name is validated, injection is rejected.
        self._send(404, "<html><body>404 Not Found</body></html>")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
