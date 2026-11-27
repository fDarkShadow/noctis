#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote
from mocklib import serve

VULN_MODE = os.environ.get("GEOSERVER_MODE", "patched") == "vuln"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="application/xml"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        value_ref = unquote(params.get("valueReference", [""])[0])
        request_type = params.get("request", [""])[0]

        if request_type == "GetPropertyValue" and "exec(" in value_ref:
            if VULN_MODE:
                body = (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<wfs:ValueCollection xmlns:wfs="http://www.opengis.net/wfs/2.0">'
                    '<wfs:member><sf:archsites xmlns:sf="http://cite.opengeospatial.org/gmlsf">'
                    '<sf:str1>NOCTIS_GEOSERVER_RCE</sf:str1>'
                    '</sf:archsites></wfs:member>'
                    '</wfs:ValueCollection>'
                )
                self._send(200, body)
            else:
                body = (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<ows:ExceptionReport xmlns:ows="http://www.opengis.net/ows/1.1">'
                    '<ows:Exception exceptionCode="InvalidParameterValue">'
                    '<ows:ExceptionText>Invalid property name</ows:ExceptionText>'
                    '</ows:Exception></ows:ExceptionReport>'
                )
                self._send(200, body)
        else:
            self._send(200, "<html><title>GeoServer</title></html>", ct="text/html")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
