#!/usr/bin/env python3
# Mock for Symantec Endpoint Protection Manager — CVE-2013-5014 / CVE-2013-5015
# (XXE -> SQL injection -> xp_cmdshell, time-based blind).
#
# Both modes serve a *realistic* SEPM: GET / returns the product fingerprint
# (">Symantec Endpoint Protection Manager<" + "Symantec Corporation<") and
# /servlet/ConsoleServlet?ActionType=ConsoleLog accepts the multipart POST.
#
#   vuln:    when the POST body carries the real XXE+SQLi payload
#            (xp_cmdshell('ping -n N 127.0.0.1')), the injected command runs and
#            blocks the response for ~N-1 seconds — exactly the delay the NASL
#            measures. No payload -> no delay, so a bare probe never triggers.
#   patched: the same endpoint answers immediately and never executes the
#            payload, so neither timing round is delayed -> zero findings.
#
# Detection keys on the differential delay (command execution), NOT on product
# presence or any reflected input — both of which are identical across modes.
import os, re, ssl, time, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("SYMANTEC_EPM_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

CONSOLE_PATH = "/servlet/ConsoleServlet"

# Same fingerprint for vuln and patched (a patched manager is still SEPM).
FINGERPRINT_PAGE = (
    "<html><head><title>Symantec Endpoint Protection Manager</title></head>"
    "<body class=\"sepm-console\">"
    "<div id=\"product\">>Symantec Endpoint Protection Manager<</div>"
    "<div id=\"vendor\">Symantec Corporation<</div>"
    "</body></html>"
)

# Same ConsoleServlet reply in both modes — the body carries no secret; the only
# observable difference between vuln and patched is the response *time*.
CONSOLE_REPLY = (
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
    "<response><ConsoleLog status=\"accepted\"/></response>"
)

# The injected SQLi command carried through the XXE entity.
PING_RE = re.compile(rb"xp_cmdshell\('ping -n (\d+) 127\.0\.0\.1'\)")

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(length) if length else b""

    def do_GET(self):
        if self.path.split("?", 1)[0] == "/":
            self._send(200, FINGERPRINT_PAGE)
        else:
            self._send(404, "<html><body>Not found</body></html>")

    def do_POST(self):
        body = self._read_body()
        path = self.path.split("?", 1)[0]
        if path == CONSOLE_PATH:
            m = PING_RE.search(body)
            if VULN_MODE and m:
                # xp_cmdshell runs `ping -n N 127.0.0.1`; on Windows that blocks
                # for roughly (N-1) seconds before the servlet replies.
                count = int(m.group(1))
                time.sleep(max(0, count - 1))
            self._send(200, CONSOLE_REPLY, ct="text/xml")
        else:
            self._send(404, "<html><body>Not found</body></html>")

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
