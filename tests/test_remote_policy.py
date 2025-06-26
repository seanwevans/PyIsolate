import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import pyisolate.policy as policy


class PolicyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        doc = "version: 0.1\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(doc.encode("utf-8"))


def test_refresh_remote(tmp_path):
    addr = ("127.0.0.1", 0)
    httpd = HTTPServer(addr, PolicyHandler)
    port = httpd.server_address[1]

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        import pyisolate.bpf.manager as mgr

        orig = mgr.BPFManager.hot_reload
        mgr.BPFManager.hot_reload = lambda *a, **k: None
        try:
            policy.refresh_remote(f"http://127.0.0.1:{port}")
        finally:
            mgr.BPFManager.hot_reload = orig
    finally:
        httpd.shutdown()
        thread.join()
