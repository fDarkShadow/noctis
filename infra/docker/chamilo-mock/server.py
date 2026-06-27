#!/usr/bin/env python3
import os
import re
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("CHAMILO_MODE", "patched") == "vuln"
ENDPOINT = "/main/webservices/additional_webservices.php"
SHELL_CHARS = ('`', '|', ';')

FILE_NAME_RE = re.compile(
    r'<key[^>]*>file_name</key>\s*<value[^>]*>([^<]*)</value>',
    re.DOTALL,
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/xml; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _soap_response(self, content):
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
            "<SOAP-ENV:Body>"
            "<ns1:wsConvertPptResponse>"
            f"<return>{content}</return>"
            "</ns1:wsConvertPptResponse>"
            "</SOAP-ENV:Body>"
            "</SOAP-ENV:Envelope>"
        )
        return body

    def _soap_fault(self, msg):
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
            "<SOAP-ENV:Body>"
            "<SOAP-ENV:Fault>"
            "<faultcode>SOAP-ENV:Client</faultcode>"
            f"<faultstring>{msg}</faultstring>"
            "</SOAP-ENV:Fault>"
            "</SOAP-ENV:Body>"
            "</SOAP-ENV:Envelope>"
        )
        return body

    def do_POST(self):
        if self.path != ENDPOINT:
            self._send(404, "Not found", "text/plain")
            return

        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")

        file_name = ""
        m = FILE_NAME_RE.search(raw)
        if m:
            file_name = m.group(1)

        has_metachar = any(c in file_name for c in SHELL_CHARS)

        if VULN_MODE and has_metachar:
            result = subprocess.run(
                "cat /etc/passwd", shell=True, capture_output=True, text=True
            )
            self._send(200, self._soap_response(result.stdout))
        elif VULN_MODE:
            self._send(200, self._soap_response(""))
        else:
            if has_metachar:
                self._send(200, self._soap_fault("Invalid file name: contains illegal characters"))
            else:
                self._send(200, self._soap_response(""))

    def do_GET(self):
        self._send(404, "Not found", "text/plain")


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/certs/server.crt", "/certs/server.key")
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    mode = "vuln" if VULN_MODE else "patched"
    print(f"Chamilo mock on :80/:443 (mode={mode})", flush=True)
    https = _make_https_server(443)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
