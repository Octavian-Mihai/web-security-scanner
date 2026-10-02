from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


class Site:
    """A tiny configurable HTTP server: routes map path -> (status, headers, body)."""

    def __init__(self):
        self.routes: dict[str, tuple[int, list[tuple[str, str]], str]] = {}
        self.reflect_origin = False
        site = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                status, headers, body = site.routes.get(
                    self.path, site.routes.get("*", (404, [], "not found")))
                self.send_response(status)
                for k, v in headers:
                    self.send_header(k, v)
                origin = self.headers.get("Origin")
                if site.reflect_origin and origin:
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Access-Control-Allow-Credentials", "true")
                data = body.encode()
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(data)

            def version_string(self):
                return "test"  # the stdlib default discloses version and trips WSS009

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


@pytest.fixture
def site():
    s = Site()
    yield s
    s.close()


HARDENED = [
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=()"),
]
