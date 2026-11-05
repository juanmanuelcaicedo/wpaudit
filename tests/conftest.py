import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
os.environ["NO_PROXY"] = "127.0.0.1,localhost"

from fake_wp_server import H  # noqa: E402

from wpaudit import checks  # noqa: E402


def serve(handler):
    server = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def offline_api(monkeypatch):
    def fail(*_args, **_kwargs):
        raise checks.requests.ConnectionError("sin red")
    monkeypatch.setattr(checks, "wp_api", fail)


@pytest.fixture
def fake_wp(offline_api):
    server = serve(H)
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture
def custom_site(offline_api):
    servers = []

    def start(respond):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def _reply(self):
                code, headers, body = respond(self.path)
                self.send_response(code)
                for key, value in headers.items():
                    self.send_header(key, value)
                data = body.encode()
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            do_GET = do_POST = do_OPTIONS = _reply

        server = serve(Handler)
        servers.append(server)
        return f"http://127.0.0.1:{server.server_port}"
    yield start
    for server in servers:
        server.shutdown()
