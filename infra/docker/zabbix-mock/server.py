#!/usr/bin/env python3
# Zabbix frontend mock for CVE-2013-5743 (httpmon.php applications SQLi).
# Installed under /zabbix/ like a distro package. Vuln: the quote in
# "applications" breaks the SQL query and the DB error is echoed.
# Patched: the parameter is validated and a normal page is rendered.
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs

VULN_MODE = os.environ.get("ZABBIX_MODE", "patched") == "vuln"

PAGE = ("<html><head><title>Zabbix: Status of Web monitoring</title></head>"
        "<body><div class=\"header\">ZABBIX</div>{}</body></html>")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html; charset=UTF-8"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path == "/zabbix/httpmon.php":
            apps = parse_qs(parts.query).get("applications", [""])[0]
            if VULN_MODE and "'" in apps:
                err = ("<div class=\"msg-bad\">Error in query [SELECT DISTINCT h.hostid,h.name "
                       "FROM hosts h,applications a WHERE a.applicationid IN (" + apps + ") "
                       "AND h.hostid=a.hostid] [You have an error in your SQL syntax; check the "
                       "manual that corresponds to your MySQL server version for the right "
                       "syntax to use near ''' at line 1]</div>")
                self._send(200, PAGE.format(err))
            else:
                self._send(200, PAGE.format("<table><tr><td>No web scenarios defined.</td></tr></table>"))
        elif parts.path in ("/zabbix/", "/zabbix/index.php"):
            self._send(200, PAGE.format("<form>Username / Password</form>"))
        else:
            self._send(404, "<html><body>Not Found</body></html>")


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
