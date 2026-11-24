"""Shared bootstrap for noctis Python mocks (baked into noctis/py-mock-base).

    from mocklib import serve
    ...
    if __name__ == "__main__":
        serve(Handler, HTTPServer)

serves `Handler` on HTTP:80 and on HTTPS:443 with the self-signed cert that the base
image generates in /certs — the same thing every mock's `_make_https_server()` +
`threading.Thread` block used to do by hand.
"""
import ssl
import threading
from http.server import HTTPServer

CERT_FILE = "/certs/server.crt"
KEY_FILE = "/certs/server.key"


def make_https_server(handler, port=443, server_cls=HTTPServer):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)
    srv = server_cls(("0.0.0.0", port), handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


def serve(handler, server_cls=HTTPServer, http_port=80, https_port=443):
    https = make_https_server(handler, https_port, server_cls)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    server_cls(("0.0.0.0", http_port), handler).serve_forever()
