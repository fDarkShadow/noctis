"""Mock Log4Shell-vulnerable Java app — CVE-2021-44228."""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("LOG4SHELL_MODE", "vuln") == "vuln"

VULN_VERSION = "2.14.1"
PATCHED_VERSION = "2.17.1"

POM_TEMPLATE = (
    "groupId=org.apache.logging.log4j\n"
    "artifactId=log4j-core\n"
    "version={version}\n"
)

POM_PATH = "/META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties"


class Log4ShellHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == POM_PATH:
            version = VULN_VERSION if VULN_MODE else PATCHED_VERSION
            body = POM_TEMPLATE.format(version=version).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b"OK\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


def _make_https_server(handler, port):
    import ssl
    srv = HTTPServer(("0.0.0.0", port), handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/app/cert.pem", "/app/key.pem")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    import threading
    mode = "vuln" if VULN_MODE else "patched"
    http_srv = HTTPServer(("0.0.0.0", 80), Log4ShellHandler)
    https_srv = _make_https_server(Log4ShellHandler, 443)
    print(f"Log4Shell mock on :80/:443 (mode={mode}, version={VULN_VERSION if VULN_MODE else PATCHED_VERSION})", flush=True)
    threading.Thread(target=http_srv.serve_forever, daemon=True).start()
    https_srv.serve_forever()
