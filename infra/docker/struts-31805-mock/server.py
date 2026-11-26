#!/usr/bin/env python3
# Mock for CVE-2021-31805 (Apache Struts2 S2-062 — forced double OGNL eval RCE).
# Ported detection target of OpenVAS NASL 2022/apache/gb_struts_s2-062_active.nasl.
#
# Both modes serve the Struts2 Showcase application realistically (a landing page
# at the /struts2-showcase/ fallback base path the NASL always probes), because a
# patched Struts still ships Showcase — its presence is not the vulnerability.
#
# Vuln mode:    POST /struts2-showcase/ — when the multipart body carries the
#               S2-062 OGNL payload (the member-access exclude-list stripping plus
#               freemarker.template.utility.Execute running `id`), the server
#               emulates the forced second OGNL evaluation and reflects the output
#               of the `id` command: "uid=0(root) gid=0(root) groups=0(root)"
#               (HTTP 200). A request WITHOUT the OGNL payload gets the ordinary
#               Showcase page with no command output — so the TP proves the
#               payload matters.
# Patched mode: same Showcase page, but the second OGNL evaluation never happens
#               and the command output is never reflected (ordinary page) — so the
#               TN exercises the fix on a real, product-serving instance.
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("STRUTS_31805_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

SHOWCASE_BODY = (
    "<!DOCTYPE html>\n<html><head><title>Struts2 Showcase</title></head>\n"
    "<body><h1>Struts2 Showcase</h1>\n"
    "<p>Welcome to the Apache Struts2 Showcase sample application.</p>\n"
    "</body></html>\n"
)

# The reflected output of the injected Linux `id` command, exactly as the NASL's
# exploit_commands() helper expects it to match (uid=[0-9]+.*gid=[0-9]+).
ID_OUTPUT = "uid=0(root) gid=0(root) groups=0(root)\n"


def _has_s2062_payload(raw_body):
    """True when the multipart body carries the S2-062 forced-OGNL injection.

    The real payload strips excludedPackageNames/excludedClasses from the member
    access map and runs an OS command via freemarker.template.utility.Execute.
    Require those signatures AND the injected `id` command so the TP proves the
    payload matters (a benign/empty POST must not reflect the command output).
    """
    try:
        decoded = raw_body.decode("utf-8", "replace")
    except Exception:
        return False
    return (
        ("excludedPackageNames" in decoded)
        and ("freemarker.template.utility.Execute" in decoded)
        and ("'id'" in decoded)
    )


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Gate / landing page (served by BOTH modes).
        if self.path.rstrip("/") == "/struts2-showcase" or self.path == "/struts2-showcase/":
            self._send(200, SHOWCASE_BODY)
        else:
            self._send(404, "Not found")

    def do_POST(self):
        body = self._read_body()
        if self.path.rstrip("/") == "/struts2-showcase" or self.path == "/struts2-showcase/":
            # Vulnerable Struts2 performs the forced second OGNL evaluation and
            # executes the injected command, reflecting its output. Only emit the
            # `id` output when the S2-062 payload is present.
            if VULN_MODE and _has_s2062_payload(body):
                self._send(200, "<html><body>" + SHOWCASE_BODY + ID_OUTPUT + "</body></html>")
            else:
                # Patched instance (or a request without the payload): ordinary
                # Showcase page, OGNL is not re-evaluated, no command output.
                self._send(200, SHOWCASE_BODY)
        else:
            self._send(404, "Not found")


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
