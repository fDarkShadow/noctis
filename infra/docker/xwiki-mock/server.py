#!/usr/bin/env python3
import os, ssl, threading, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("XWIKI_MODE", "patched") == "vuln"

RSS_VULN = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>XWiki wiki</title>
<item><description>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin</description></item>
</channel></rss>"""

RSS_PATCHED = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>XWiki wiki</title></channel></rss>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="application/rss+xml"):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        solr_paths = ["/bin/get/Main/SolrSearch", "/xwiki/bin/get/Main/SolrSearch"]
        if path not in solr_paths:
            self._send(404, b"Not found", "text/plain")
            return

        text_param = params.get("text", [""])[0]

        if VULN_MODE and ("groovy" in text_param or "async" in text_param):
            self._send(200, RSS_VULN)
        else:
            self._send(200, RSS_PATCHED)

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
