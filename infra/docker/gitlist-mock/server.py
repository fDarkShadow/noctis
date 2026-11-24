#!/usr/bin/env python3
"""Mock for CVE-2014-4511 (gitlist) — OpenVAS NASL 2014/gb_gitlist_rce_06_14.nasl (GPL-2.0-only)."""
import os, ssl, threading, urllib.parse, base64, html
from http.server import BaseHTTPRequestHandler, HTTPServer
CFG = {'kind': 'sqli', 'gate': '%60id%60', 'pre': {'path': '/', 'body': '<html><body><a href="/example">example</a> Powered by <a href="https://gitlist.org">GitList</a></body></html>'}, 'url_path': '/example/blame/master/%22%22</%60id%60', 'witness': 'uid=0(root) gid=0(root) groups=0(root)'}
VULN = os.environ.get('GITLIST_MODE', "patched") == "vuln"
BENIGN = "<html><head><title>OK</title></head><body>Service operational.</body></html>"
class H(BaseHTTPRequestHandler):
    uploaded = False
    def log_message(self,*a): pass
    def _s(self, code, b, hdrs=None, ct="text/html"):
        if isinstance(b,str): b=b.encode()
        self.send_response(code); self.send_header("Content-Type",ct)
        self.send_header("Content-Length",str(len(b)))
        for k,v in (hdrs or {}).items(): self.send_header(k,v)
        self.end_headers(); self.wfile.write(b)
    def _body(self):
        n=int(self.headers.get("Content-Length",0) or 0)
        return self.rfile.read(n).decode("latin1") if n else ""
    def do_GET(self):
        raw=self.path; p=raw.split("?")[0]
        pre=CFG.get("pre")
        if pre and p==pre["path"]:
            return self._s(200, pre["body"])           # product page, both modes
        k=CFG["kind"]
        if k in ("get","sqli","lfi_b64"):
            if p!=CFG["url_path"]: return self._s(404,"Not found")
            if VULN and self._gate(raw, ""): return self._s(200, CFG["witness"])
            return self._s(200, BENIGN)
        if k=="xss":
            if p!=CFG["url_path"]: return self._s(404,"Not found")
            q=urllib.parse.urlparse(raw).query
            v=urllib.parse.parse_qs(q, keep_blank_values=True).get(CFG["param"],[""])[0]
            if VULN and CFG["gate"] in raw:
                return self._s(200, "<html><body>Error: "+v+" <h1>SSO Error</h1></body></html>")
            return self._s(200, "<html><body>Error: "+html.escape(v)+" <h1>SSO Error</h1></body></html>")
        if k=="upload":
            if p==CFG["get_path"]:
                if VULN and H.uploaded: return self._s(200, CFG["witness"])
                return self._s(404,"Not found")
            return self._s(200, BENIGN)
        if k=="login":
            return self._s(200, BENIGN)
        return self._s(404,"Not found")
    def do_POST(self):
        raw=self.path; p=raw.split("?")[0]; data=self._body()
        k=CFG["kind"]
        if k=="login":
            if p!=CFG["post_path"]: return self._s(404,"Not found")
            if VULN and CFG["gate"] in data:
                return self._s(200, CFG["auth_body"], hdrs={"Set-Cookie":CFG["set_cookie"]})
            return self._s(401, "<html><body>Invalid credentials.</body></html>")
        if k=="upload":
            if p==CFG["post_path"] and VULN and (CFG["gate"] in data):
                H.uploaded=True
                return self._s(200,"success")
            return self._s(200,"ok")
        return self.do_GET()
    def _gate(self, raw, data):
        k=CFG["kind"]; g=CFG.get("gate")
        if k=="lfi_b64":
            q=urllib.parse.urlparse(raw).query
            v=urllib.parse.parse_qs(q).get(CFG["param"],[""])[0]
            try: dec=base64.b64decode(v+"==").decode("latin1")
            except Exception: dec=""
            return "../" in dec and "etc/passwd" in dec
        if g is None: return True
        return g in raw
def _https(port):
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain("/certs/server.crt","/certs/server.key")
    srv=HTTPServer(("0.0.0.0",port),H); srv.socket=ctx.wrap_socket(srv.socket, server_side=True); return srv
if __name__=="__main__":
    threading.Thread(target=_https(443).serve_forever, daemon=True).start()
    HTTPServer(("0.0.0.0",80),H).serve_forever()
