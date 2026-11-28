#!/usr/bin/env python3
"""Mock for CVE-2019-1653 (Cisco Small Business RV320/RV325 config disclosure).

vuln mode  : /cgi-bin/config.exp returns a realistic exported device configuration
             (the genuine 'sysconfig' section marker plus credential fields) to an
             unauthenticated GET — exactly as an affected RV320/RV325 does.
patched mode: the same endpoint requires authentication and answers 401, so detection fails.

The export body intentionally includes secret-looking fields (admin password hash, SNMP
communities) so the TN/PII-hygiene story is honest: the feed must key on a non-secret
structural marker and must not leak those fields into findings.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN = os.environ.get("CISCO_RV_MODE", "patched") == "vuln"

# Realistic RV320/RV325 configuration export. 'sysconfig' is the genuine, non-secret
# structural marker the detection keys on; admin_pwd/snmp_*_community are secrets that a
# correct feed must NOT echo into any finding.
CONFIG_EXPORT = (
    "sysconfig\n"
    "#System\n"
    "host_name=RV320\n"
    "fw_version=1.4.2.15\n"
    "#WAN\n"
    "wan_proto=static\n"
    "wan_ip=203.0.113.10\n"
    "wan_netmask=255.255.255.0\n"
    "#LAN\n"
    "lan_ip=192.168.1.1\n"
    "lan_netmask=255.255.255.0\n"
    "#Management\n"
    "remote_management=1\n"
    "https_port=443\n"
    "#VPN\n"
    "ipsec_tunnel_enable=1\n"
    "#Accounts\n"
    "admin_name=cisco\n"
    "admin_pwd=$1$mERr$sB7v1Qk9jD8c2fLpN0aXz.\n"
    "snmp_ro_community=public\n"
    "snmp_rw_community=s3cr3t-rw-community\n"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _start(self, code):
        self._code = code
        self._hdrs = []

    def _h(self, k, v):
        self._hdrs.append((k, v))

    def _finish(self, body):
        if isinstance(body, str):
            body = body.encode("latin-1", "replace")
        self.send_response(self._code)
        for k, v in self._hdrs:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _route(self):
        path = self.path.split("?", 1)[0]
        if path in ("/cgi-bin/config.exp", "/cgi-bin/export"):
            if VULN:
                self._start(200)
                self._h("Content-Type", "application/octet-stream")
                self._h("Content-Disposition", 'attachment; filename="config.exp"')
                self._finish(CONFIG_EXPORT)
                return
            # patched: the export now requires authentication
            self._start(401)
            self._h("WWW-Authenticate", 'Basic realm="RV320"')
            self._h("Content-Type", "text/html")
            self._finish("<html><body>401 Unauthorized</body></html>\n")
            return
        self._start(404)
        self._h("Content-Type", "text/plain")
        self._finish("Not found\n")

    def do_GET(self):
        self._route()

    def do_POST(self):
        self._route()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
