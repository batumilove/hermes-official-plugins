"""Exercise real TLS, authentication, redirect refusal and bounded reads on loopback."""
import json
import shutil
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from langfuse_plugin import backend_readback as module


@pytest.fixture
def endpoint(tmp_path):
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl required to provision a disposable loopback TLS identity")
    key, cert = tmp_path / "test-only.key", tmp_path / "test-only.pem"
    subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
                    "-keyout", str(key), "-out", str(cert)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    state = {"requests": [], "status": 200, "body": json.dumps({"data": [], "meta": {}}).encode()}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            state["requests"].append((self.path, self.headers.get("Authorization")))
            self.send_response(state["status"])
            if state["status"] == 302:
                self.send_header("Location", state["url"] + "/redirect-target")
            framing = state.get("framing", "length")
            if framing == "length":
                self.send_header("Content-Length", str(state.get("declared_length", len(state["body"]))))
            elif framing == "chunked":
                self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            try:
                if framing == "chunked":
                    for offset in range(0, len(state["body"]), 65536):
                        chunk = state["body"][offset:offset + 65536]
                        self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                    self.wfile.write(b"0\r\n\r\n")
                else:
                    self.wfile.write(state["body"])
            except (BrokenPipeError, ConnectionResetError):
                pass  # oversized-body refusal intentionally closes the consumer first

    server = HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    state["url"] = f"https://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield state, cert
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def trusted_reader(endpoint, monkeypatch):
    state, cert = endpoint
    trusted = ssl.create_default_context(cafile=str(cert))
    monkeypatch.setattr(module.ssl, "create_default_context", lambda: trusted)
    return module.ObservationReader(state["url"], "pk-synthetic", "sk-synthetic",
                                     project_id="synthetic-project")


def test_real_tls_and_basic_auth(endpoint, monkeypatch):
    state, _ = endpoint
    reader = trusted_reader(endpoint, monkeypatch)
    result = reader.read("a" * 32, start_time=1000, end_time=1010)
    assert result.complete and result.observations == ()
    path, auth = state["requests"][0]
    assert path.startswith("/api/public/v2/observations?")
    assert auth == "Basic cGstc3ludGhldGljOnNrLXN5bnRoZXRpYw=="


def test_untrusted_certificate_is_refused(endpoint):
    state, _ = endpoint
    reader = module.ObservationReader(state["url"], "pk-synthetic", "sk-synthetic",
                                       project_id="synthetic-project")
    with pytest.raises(module.ReadbackError, match="transport_failed"):
        reader.read("a" * 32, start_time=1000, end_time=1010)
    assert state["requests"] == []


def test_redirect_does_not_forward_authentication(endpoint, monkeypatch):
    state, _ = endpoint
    state["status"] = 302
    reader = trusted_reader(endpoint, monkeypatch)
    with pytest.raises(module.ReadbackError, match="redirect_refused"):
        reader.read("a" * 32, start_time=1000, end_time=1010)
    assert len(state["requests"]) == 1


def test_valid_json_prefix_of_truncated_response_is_not_complete(endpoint, monkeypatch):
    state, _ = endpoint
    state["declared_length"] = len(state["body"]) + 10
    reader = trusted_reader(endpoint, monkeypatch)
    with pytest.raises(module.ReadbackError, match="incomplete_response"):
        reader.read("a" * 32, start_time=1000, end_time=1010)


def test_partial_http_success_is_not_a_complete_query(endpoint, monkeypatch):
    state, _ = endpoint
    state["status"] = 206
    reader = trusted_reader(endpoint, monkeypatch)
    with pytest.raises(module.ReadbackError, match="incomplete_response"):
        reader.read("a" * 32, start_time=1000, end_time=1010)


@pytest.mark.parametrize("status, body, reason", [(503, b"SENSITIVE_SENTINEL", "transport_failed"),
                                                (200, b"x" * 1048577, "response_too_large")],
                         ids=["http-error", "oversize"])
def test_actual_http_failure_or_oversize_is_content_free(endpoint, monkeypatch, status, body, reason):
    state, _ = endpoint
    state.update(status=status, body=body)
    reader = trusted_reader(endpoint, monkeypatch)
    with pytest.raises(module.ReadbackError) as caught:
        reader.read("a" * 32, start_time=1000, end_time=1010)
    assert str(caught.value) == reason


@pytest.mark.parametrize("framing", ["eof", "chunked"])
def test_actual_streaming_response_without_content_length_is_bounded(endpoint, monkeypatch, framing):
    state, _ = endpoint
    state.update(framing=framing, body=b"x" * 1048577)
    reader = trusted_reader(endpoint, monkeypatch)
    with pytest.raises(module.ReadbackError, match="response_too_large"):
        reader.read("a" * 32, start_time=1000, end_time=1010)
