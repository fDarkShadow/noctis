#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

VULN_MODE = os.environ.get("CRAFTCMS_MODE", "patched") == "vuln"

CRAFT_NORMAL = b"<html><body><h1>Craft CMS</h1><p>Welcome to Craft CMS.</p></body></html>"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

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
        params = parse_qs(parsed.query, keep_blank_values=True)
        config_path = params.get("--configPath", [None])[0]

        if VULN_MODE and config_path is not None:
            error_body = (
                "PHP Fatal error: Uncaught yii\\base\\InvalidConfigException: "
                "mkdir({cp}): Permission denied in /var/www/vendor/craftcms/cms/src/Craft.php:123"
            ).format(cp=config_path)
            self._send(503, error_body, "text/plain")
        else:
            self._send(200, CRAFT_NORMAL)

    def do_POST(self):
        self._send(200, CRAFT_NORMAL)


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
