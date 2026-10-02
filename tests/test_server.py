"""The local server must reject requests without the launch token or with a foreign Host header."""
import http.client
import json
import threading

import pytest

import server


class FakeSession:
    results = None

    def snapshot(self):
        return {"phase": "connect"}

    def act(self, payload):
        return {"ok": True, "echo": payload.get("type")}


@pytest.fixture(scope="module")
def port():
    server.SESSION = FakeSession()
    httpd = server.LocalServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd.server_address[1]
    httpd.shutdown()


def request(port, method, path, headers=None, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request(method, path, body=body, headers={"Host": f"127.0.0.1:{port}", **(headers or {})})
    res = conn.getresponse()
    return res.status, res.read(), dict(res.getheaders())


def test_ui_is_public_but_locked_down(port):
    status, body, headers = request(port, "GET", "/")
    assert status == 200 and b"app.js" in body
    assert "default-src 'self'" in headers["Content-Security-Policy"]


def test_api_needs_token(port):
    assert request(port, "GET", "/api/state")[0] == 401
    assert request(port, "GET", "/api/state", {"X-Token": "wrong"})[0] == 401
    assert request(port, "GET", "/api/state", {"X-Token": server.TOKEN})[0] == 200
    assert request(port, "POST", "/api/act", {"Content-Type": "application/json"}, json.dumps({"type": "x"}))[0] == 403


def test_foreign_host_rejected(port):
    assert request(port, "GET", "/api/state", {"X-Token": server.TOKEN, "Host": "evil.example"})[0] == 403


def test_no_path_traversal(port):
    assert request(port, "GET", "/ui/../server.py")[0] == 404
    assert request(port, "GET", "/i18n/../../server.json")[0] in (401, 404)


def test_dropped_connections_leave_no_traceback(capsys):
    srv = server.LocalServer.__new__(server.LocalServer)  # handle_error needs no socket
    for exc in (BrokenPipeError(32, "Broken pipe"), ConnectionResetError(54, "reset")):
        try:
            raise exc
        except OSError:
            srv.handle_error(None, ("127.0.0.1", 1))
    assert capsys.readouterr().err == ""
    try:
        raise ValueError("real bug")
    except ValueError:
        srv.handle_error(None, ("127.0.0.1", 1))
    assert "ValueError: real bug" in capsys.readouterr().err
