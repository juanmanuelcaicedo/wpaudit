#!/usr/bin/env python3
"""Servidor WordPress SIMULADO y deliberadamente inseguro, solo para probar wpaudit en local.

    python3 tests/fake_wp_server.py 8099   →   python3 -m wpaudit http://127.0.0.1:8099 --authorized --profile quick
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

HOME = """<!doctype html><html><head>
<meta name="generator" content="WordPress 5.0.3" />
<link rel="stylesheet" href="/wp-content/plugins/contact-form-7/style.css?ver=5.1">
<script src="/wp-content/themes/twentytwenty/app.js?ver=1.0"></script>
<script src="https://cdn.example.net/lib.js"></script>
<img src="http://insecure.example.org/pic.png">
</head><body><h1>Sitio de prueba</h1><a href="/sample-page/">Muestra</a></body></html>"""

LISTING = "<html><head><title>Index of /wp-content/uploads</title></head><body><h1>Index of /wp-content/uploads</h1></body></html>"


class H(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.29 (Ubuntu)"

    def _send(self, code=200, body="", ctype="text/html", extra=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.send_header("Set-Cookie", "sessid=abc123; Path=/")
        # Como el núcleo de WordPress: la REST API refleja el Origin y permite credenciales
        origin = self.headers.get("Origin")
        if origin and self.path.startswith("/wp-json"):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass

    def do_OPTIONS(self):
        self._send(200, "", extra={"Allow": "GET,POST,OPTIONS,TRACE,PUT"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        if self.path.startswith("/xmlrpc.php"):
            methods = ["system.listMethods", "system.multicall", "pingback.ping", "wp.getUsersBlogs"]
            xml = "<?xml version='1.0'?><methodResponse><params><param><value><array><data>" + \
                  "".join(f"<value><string>{m}</string></value>" for m in methods) + "</data></array></value></param></params></methodResponse>"
            return self._send(200, xml, "text/xml")
        self._send(404, "nope")

    def do_GET(self):
        p = self.path.split("?")[0]
        if self.path.startswith("/?author=1"):
            return self._send(302, "", extra={"Location": "/author/admin/"})
        if p in ("/", "/sample-page/"):
            return self._send(200, HOME)
        if p == "/wp-json/wp/v2/users":
            return self._send(200, json.dumps([{"id": 1, "name": "Admin", "slug": "admin"}, {"id": 2, "name": "Ana", "slug": "ana"}]), "application/json")
        if p == "/readme.html":
            return self._send(200, "<html>WordPress<br>Version 5.0.3</html>")
        if p == "/wp-content/plugins/contact-form-7/readme.txt":
            return self._send(200, "=== Contact Form 7 ===\nStable tag: 5.1\n", "text/plain")
        if p == "/wp-content/themes/twentytwenty/style.css":
            return self._send(200, "/*\nTheme Name: Twenty Twenty\nVersion: 1.0\n*/", "text/css")
        if p == "/wp-config.php.bak":
            return self._send(200, "<?php\ndefine('DB_NAME','wp');\ndefine('DB_PASSWORD','secret');", "text/plain")
        if p == "/wp-content/debug.log":
            return self._send(200, "[05-Oct-2026 10:00:00 UTC] PHP Warning:  Undefined index in /var/www/x.php", "text/plain")
        if p == "/wp-content/uploads/":
            return self._send(200, LISTING)
        if p == "/wp-login.php":
            if "register" in self.path:
                return self._send(200, '<form id="registerform">user_login</form>')
            return self._send(200, '<form><input name="log" id="user_login"></form>')
        if p == "/wp-cron.php":
            return self._send(200, "")
        if p == "/author/admin/" or p.startswith("/?author"):
            return self._send(200, "ok")
        self._send(404, "not found")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    HTTPServer(("127.0.0.1", port), H).serve_forever()
