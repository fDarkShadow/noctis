#!/usr/bin/env python3
"""Oracle WebLogic Server mock for CVE-2019-2725 (noctis).

The wls-wsat coordinator deserializes the SOAP <work:WorkContext> element with
java.beans.XMLDecoder. This is the genuine, benign *detection* behaviour this
mock reproduces (it does NOT execute any command):

  When a vulnerable wls-wsat endpoint is handed a WorkContext/XMLDecoder
  envelope that references a class it cannot resolve, XMLDecoder tries to
  instantiate that class, fails, and WebLogic returns an HTTP 500 SOAP fault
  whose <faultstring> reflects the exact class name that was supplied — e.g.
  `java.lang.ClassNotFoundException: <the name from our envelope>`. A patched
  server removes/guards the wls-wsat endpoint (404) or never processes the
  WorkContext, so the supplied class name is never echoed back.

WEBLOGIC_2725_MODE:
  vuln     /wls-wsat/* processes the WorkContext/XMLDecoder envelope and
           reflects the UNRESOLVABLE class name taken FROM THE POSTED BODY in a
           500 SOAP ClassNotFoundException fault.
  patched  the wls-wsat endpoint returns 404 and never reflects anything.

The reflected string is derived entirely from the request the scanner sent, not
from a constant the mock invents: change the class marker the feed sends and the
fault reflects the new marker. This mirrors a real vulnerable WebLogic, on which
the same unresolvable-class probe yields the same reflected ClassNotFoundException
— so the feed's match proves the endpoint processed OUR input, not a fixture.
"""
import os
import re
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

# Classes XMLDecoder resolves without error — a reference to any of these is not
# what triggers the reflected ClassNotFoundException on a real target.
RESOLVABLE = {
    "java.beans.XMLDecoder",
    "java.lang.String",
    "java.lang.ProcessBuilder",
    "java.util.ArrayList",
    "java.util.HashMap",
}

CLASS_ATTR = re.compile(r'class\s*=\s*"([^"]+)"')

NOT_FOUND = "<html><head><title>Error 404--Not Found</title></head><body></body></html>"


def unresolvable_class(body):
    """Return the first class="..." reference XMLDecoder could not load, exactly
    as it appears in the posted body (this is what a real server reflects)."""
    for name in CLASS_ATTR.findall(body):
        if name not in RESOLVABLE:
            return name
    return None


def fault_500(classname):
    # Mirrors the WebLogic SOAP fault returned when XMLDecoder fails to resolve a
    # referenced class. The class name is taken verbatim from the request body.
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">'
        "<S:Header/><S:Body>"
        '<S:Fault xmlns:ns4="http://www.w3.org/2003/05/soap-envelope">'
        "<faultcode>S:Server</faultcode>"
        "<faultstring>java.lang.ClassNotFoundException: " + classname + "</faultstring>"
        "</S:Fault></S:Body></S:Envelope>"
    )


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
        # reaches wls-wsat: endpoint present AND the request carries the
        # XMLDecoder/WorkContext deserialization envelope.
        if (
            MODE == "vuln"
            and path in WSAT_PATHS
            and "WorkContext" in body
            and "java.beans.XMLDecoder" in body
        ):
            name = unresolvable_class(body)
            if name is not None:
                # Reflect the unresolvable class name taken from OUR request.
                self._send(500, fault_500(name), "text/xml; charset=UTF-8")
                return
            # WorkContext processed but nothing unresolvable to report — a
            # vulnerable server still accepts it; return a generic fault with no
            # reflected marker (the feed's marker-based match will not fire).
            self._send(
                500,
                fault_500("weblogic.wsee.jaxws.workcontext.WorkContextXmlInputAdapter"),
                "text/xml; charset=UTF-8",
            )
        else:
            self._send(404, NOT_FOUND, "text/html")

    def do_GET(self):
        self._send(404, NOT_FOUND, "text/html")


if __name__ == "__main__":
    serve(Handler, HTTPServer)   # HTTP:80 + HTTPS:443 (cert from the base image)
