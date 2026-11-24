#!/usr/bin/env python3
# Mock for Ektron CMS < 8.02 SP5 RCE — CVE-2012-5357
#
# Models the ContentDesigner AJAX transform endpoint
#   /WorkArea/ContentDesigner/ekajaxtransform.aspx
# which reads the `xml` and `xslt` form fields and runs the stylesheet through
# XslCompiledTransform.
#
# Vuln mode (Ektron < 8.02 SP5): scripting is enabled in the transform, so a
#   stylesheet carrying an <msxsl:script language="C#"> block executes. The
#   mock only emits the injected command output (ipconfig → "Windows IP
#   Configuration") when the POSTed xslt ACTUALLY contains the C# script block
#   AND the ipconfig command — i.e. only when the real NASL payload is present.
#   A missing/benign stylesheet just transforms to empty, proving the payload
#   (not a bare request) is what triggers RCE.
#
# Patched mode (SP5+): the SAME endpoint is served with the SAME product
#   fingerprint and still returns HTTP 200, but scripting is disabled in the
#   transform, so the <msxsl:script> block is rejected and NO command output is
#   produced (the server returns a transform error). The marker never appears,
#   so the TN proves the feed does not fire on a real, non-vulnerable Ektron.
import os, ssl, threading
from urllib.parse import parse_qs
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("EKTRON_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

TRANSFORM_PATH = "/WorkArea/ContentDesigner/ekajaxtransform.aspx"
# Install roots the real product (and the NASL) use; the endpoint lives under
# each of them. Serve all of them so the feed's dir loop reaches the product
# wherever it is mounted.
INSTALL_ROOTS = ("", "/cms", "/cms400min", "/cms400.net", "/cms400")

# Output of `ipconfig` on Windows — produced only when the injected C# script
# actually executes server-side.
IPCONFIG_OUTPUT = (
    "\r\nWindows IP Configuration\r\n\r\n"
    "Ethernet adapter Local Area Connection:\r\n\r\n"
    "   Connection-specific DNS Suffix  . :\r\n"
    "   IPv4 Address. . . . . . . . . . . : 10.0.0.5\r\n"
    "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\r\n"
    "   Default Gateway . . . . . . . . . : 10.0.0.1\r\n"
)

# Realistic product fingerprint served on the front page in both modes.
EKTRON_HOMEPAGE = (
    "<html><head><title>Ektron CMS400.NET</title></head>"
    "<body>Ektron Content Management System</body></html>"
)


def _is_transform_endpoint(path):
    # Strip query string, then check the path ends with the transform endpoint
    # under any of the known install roots.
    p = path.split("?", 1)[0]
    for root in INSTALL_ROOTS:
        if p == root + TRANSFORM_PATH:
            return True
    return False


def _payload_executes(body_bytes):
    """True only when the POSTed form carries the real exploit stylesheet:
    an xslt field containing an <msxsl:script> C# block that runs ipconfig."""
    try:
        form = parse_qs(body_bytes.decode("utf-8", "replace"))
    except Exception:
        return False
    xslt_values = form.get("xslt", [])
    if not xslt_values:
        return False
    xslt = xslt_values[0]
    return ("msxsl:script" in xslt) and ("ipconfig" in xslt)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, body, ct="text/plain", extra_headers=None):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "Microsoft-IIS/7.5")
        self.send_header("X-Powered-By", "ASP.NET")
        for k, v in (extra_headers or {}).items(): self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        if _is_transform_endpoint(self.path):
            executes = _payload_executes(body)
            if VULN_MODE:
                if executes:
                    # Scripting enabled → the injected C# runs ipconfig and the
                    # transform output is the command's stdout.
                    self._send(200, IPCONFIG_OUTPUT, ct="text/xml; charset=utf-8")
                else:
                    # Endpoint exists but no script payload → empty transform.
                    self._send(200, "", ct="text/xml; charset=utf-8")
            else:
                # Patched (SP5+): endpoint is served, product fingerprint intact,
                # but XslCompiledTransform runs with scripting DISABLED, so the
                # <msxsl:script> block is rejected — no command output, ever.
                if executes:
                    self._send(
                        200,
                        "<?xml version=\"1.0\"?><error>Transform failed: "
                        "script execution is not allowed (XsltSettings.EnableScript=false).</error>",
                        ct="text/xml; charset=utf-8",
                    )
                else:
                    self._send(200, "", ct="text/xml; charset=utf-8")
        else:
            self._send(404, "Not found")

    def do_GET(self):
        p = self.path.split("?", 1)[0]
        if p == "/" or p.endswith("/Login.aspx"):
            self._send(200, EKTRON_HOMEPAGE, ct="text/html")
        elif _is_transform_endpoint(self.path):
            # The transform endpoint expects a POST; a GET returns the product's
            # method-not-allowed page (still a real, fingerprintable endpoint).
            self._send(405, "Method Not Allowed", ct="text/html")
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
