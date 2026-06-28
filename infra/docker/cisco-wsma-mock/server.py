#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("CISCO_MODE", "patched") == "vuln"

SOAP_VULN_RESPONSE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<SOAP:Envelope xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">'
    '<SOAP:Body>'
    '<response correlator="exec1" xmlns="urn:cisco:wsma-exec">'
    '<execLog>'
    '<dialogueLog>'
    '<sent>show version</sent>'
    '<received><text>Cisco IOS XE Software, Version 17.09.04</text></received>'
    '</dialogueLog>'
    '</execLog>'
    '</response>'
    '</SOAP:Body>'
    '</SOAP:Envelope>'
)

WSMA_PATH = "/webui_wsma_Http"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/xml"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        # URL-decode %77eb%75i_%77sma_Http → webui_wsma_Http
        # Python's BaseHTTPRequestHandler does not URL-decode self.path, so
        # we match both the encoded and decoded forms.
        path_decoded = self.path.split("?")[0]
        try:
            from urllib.parse import unquote
            path_decoded = unquote(path_decoded)
        except Exception:
            pass

        if path_decoded == WSMA_PATH:
            if VULN_MODE:
                self._send(200, SOAP_VULN_RESPONSE)
            else:
                self._send(401, "Unauthorized", "text/plain")
        else:
            self._send(404, "Not found", "text/plain")

    def do_GET(self):
        self._send(404, "Not found", "text/plain")


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/certs/server.crt", "/certs/server.key")
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    https = _make_https_server(443)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
