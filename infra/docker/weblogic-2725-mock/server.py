#!/usr/bin/env python3
"""Oracle WebLogic Server mock for CVE-2019-2725 (noctis).

The wls-wsat coordinator deserializes the SOAP <work:WorkContext> with
java.beans.XMLDecoder. In the echo-variant exploit the payload runs an OS
command and the server reflects the command's stdout in the response.

WEBLOGIC_2725_MODE:
  vuln     /wls-wsat/CoordinatorPortType accepts the XMLDecoder WorkContext
           payload, runs the requested command, and reflects real id(1) output
           ("uid=0(root) gid=0(root) groups=0(root)") in a 200 SOAP response.
  patched  the wls-wsat endpoint is removed/guarded: it returns 404 and never
           reflects command output, so every detection step fails.

The feed matches the reflected id(1) output, not any mock-specific marker, so a
real vulnerable WebLogic (which reflects the same command output) would fire the
same way. A NOCTIS_WEBLOGIC_CONFIRMED marker is also embedded for operators but
is not what the feed keys on.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

MODE = os.environ.get("WEBLOGIC_2725_MODE", "patched")
if MODE not in ("vuln", "patched"):
    raise SystemExit("unknown WEBLOGIC_2725_MODE: %r" % MODE)

# wls-wsat endpoints that expose the vulnerable WorkContext deserialization.
WSAT_PATHS = (
    "/wls-wsat/CoordinatorPortType",
    "/wls-wsat/CoordinatorPortType11",
    "/wls-wsat/RegistrationPortTypeRPC",
    "/wls-wsat/ParticipantPortType",
    "/_async/AsyncResponseService",
)

# Reflected stdout of id(1) run as the WebLogic service account (root in the
# container, as on many real deployments). This is the genuine signal the feed
# confirms RCE on.
ID_OUTPUT = "uid=0(root) gid=0(root) groups=0(root)"

FAULT_200 = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    "<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\">"
    "<S:Header/><S:Body>"
    "<S:Fault xmlns:ns4=\"http://www.w3.org/2003/05/soap-envelope\">"
    "<faultcode>S:Server</faultcode>"
    "<faultstring>java.lang.ProcessBuilder; " + ID_OUTPUT + " "
    "[NOCTIS_WEBLOGIC_CONFIRMED]</faultstring>"
    "</S:Fault></S:Body></S:Envelope>"
)

NOT_FOUND = "<html><head><title>Error 404--Not Found</title></head><body></body></html>"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length).decode("utf-8", "replace") if length else ""

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        body = self._read_body()
        # Vulnerable only when the XMLDecoder WorkContext payload actually
        # reaches wls-wsat — mirror a real target: endpoint present AND the
        # request carries the XMLDecoder/WorkContext deserialization payload.
        if (
            MODE == "vuln"
            and path in WSAT_PATHS
            and "WorkContext" in body
            and "java.beans.XMLDecoder" in body
        ):
            self._send(200, FAULT_200, "text/xml; charset=UTF-8")
        else:
            self._send(404, NOT_FOUND, "text/html")

    def do_GET(self):
        self._send(404, NOT_FOUND, "text/html")


if __name__ == "__main__":
    serve(Handler, HTTPServer)   # HTTP:80 + HTTPS:443 (cert from the base image)
