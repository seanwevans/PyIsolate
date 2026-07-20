import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer

import pytest

import pyisolate.policy as policy


class PolicyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        doc = "version: 0.1\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(doc.encode("utf-8"))

    def log_message(self, format, *args):  # pragma: no cover - quiet test output
        return


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
            policy.refresh_remote(f"http://127.0.0.1:{port}", token="tok")
        finally:
            mgr.BPFManager.hot_reload = orig
    finally:
        httpd.shutdown()
        thread.join()


class SlowFirstHandler(BaseHTTPRequestHandler):
    attempts = 0

    def do_GET(self):
        type(self).attempts += 1
        if self.attempts == 1:
            time.sleep(0.2)
        doc = "version: 0.1\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        try:
            self.wfile.write(doc.encode("utf-8"))
        except BrokenPipeError:
            pass

    def log_message(self, format, *args):  # pragma: no cover - quiet test output
        return


def test_refresh_remote_retries_on_timeout(tmp_path):
    addr = ("127.0.0.1", 0)
    httpd = ThreadingHTTPServer(addr, SlowFirstHandler)
    port = httpd.server_address[1]

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        import pyisolate.bpf.manager as mgr

        orig = mgr.BPFManager.hot_reload
        mgr.BPFManager.hot_reload = lambda *a, **k: None
        try:
            policy.refresh_remote(
                f"http://127.0.0.1:{port}", token="tok", timeout=0.05, max_retries=1
            )
        finally:
            mgr.BPFManager.hot_reload = orig
    finally:
        httpd.shutdown()
        thread.join()


class AlwaysSlowHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(0.2)
        doc = "version: 0.1\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        try:
            self.wfile.write(doc.encode("utf-8"))
        except BrokenPipeError:
            pass

    def log_message(self, format, *args):  # pragma: no cover - quiet test output
        return


def test_refresh_remote_timeout_error(tmp_path):
    addr = ("127.0.0.1", 0)
    httpd = ThreadingHTTPServer(addr, AlwaysSlowHandler)
    port = httpd.server_address[1]

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        import pyisolate.bpf.manager as mgr

        orig = mgr.BPFManager.hot_reload
        mgr.BPFManager.hot_reload = lambda *a, **k: None
        try:
            with pytest.raises(TimeoutError):
                policy.refresh_remote(
                    f"http://127.0.0.1:{port}", token="tok", timeout=0.05, max_retries=1
                )
        finally:
            mgr.BPFManager.hot_reload = orig
    finally:
        httpd.shutdown()
        thread.join()


def test_refresh_remote_rejects_non_http_scheme(tmp_path):
    # urllib would happily open file:// (or ftp://) URLs; the policy fetch is
    # documented as HTTP and must not turn into a local-file read primitive.
    doc = tmp_path / "policy.yml"
    doc.write_text("version: 0.1\n", encoding="utf-8")

    with pytest.raises(ValueError, match="scheme"):
        policy.refresh_remote(doc.as_uri(), token="tok")


class OversizedHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"#" * (policy._MAX_REMOTE_POLICY_BYTES + 1)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:  # pragma: no cover - client may bail early
            pass

    def log_message(self, format, *args):  # pragma: no cover - quiet test output
        return


def test_refresh_remote_rejects_oversized_response():
    addr = ("127.0.0.1", 0)
    httpd = HTTPServer(addr, OversizedHandler)
    port = httpd.server_address[1]

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(ValueError, match="exceeds"):
            policy.refresh_remote(f"http://127.0.0.1:{port}", token="tok")
    finally:
        httpd.shutdown()
        thread.join()
