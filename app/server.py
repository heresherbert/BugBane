#!/usr/bin/env python3
"""Local web server for the BugBane scan app.

Binds to 127.0.0.1 only. Every API call must carry the per-launch token and a
localhost Host header, so web pages open in the same browser can't drive the
scanner (CSRF / DNS-rebinding). The UI loads nothing from the internet.

Run: .tools/pmd3/bin/python app/server.py [--no-browser] [--demo <history-id>]
Data (run/, history/, evidence/) lives where scan/paths.py says: the checkout, or Application Support
when running from the app bundle.
"""
import json
import mimetypes
import os
import re
import secrets
import signal
import socketserver
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

APP = Path(__file__).resolve().parent
sys.path.insert(0, str(APP))
from scan import pipeline  # noqa: E402
from scan.i18n import LANGS, I18N_DIR  # noqa: E402
from scan.report import render_report  # noqa: E402

UI = APP / "ui"
RUN = pipeline.RUN
PREFERRED_PORT = 17651
TOKEN = secrets.token_urlsafe(24)
CONFIG = json.loads((APP / "config.json").read_text()) if (APP / "config.json").exists() else {}
SESSION = None  # created in main(), after leftovers are swept


class Handler(BaseHTTPRequestHandler):
    server_version = "BugBane"

    def log_message(self, fmt, *args):  # never log requests: URLs could carry result ids
        pass

    def _host_ok(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost")

    def _token_ok(self, query):
        return secrets.compare_digest(self.headers.get("X-Token") or query.get("t", [""])[0], TOKEN)

    def _send(self, code, body, ctype="application/json", headers=None):
        data = body if isinstance(body, bytes) else (
            body.encode() if isinstance(body, str) else json.dumps(body).encode())
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                         "connect-src 'self'; frame-ancestors 'none'")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urlsplit(self.path)
        query = parse_qs(url.query)
        if not self._host_ok():
            return self._send(403, {"error": "bad host"})
        if url.path in ("/", "/index.html"):
            return self._send(200, (UI / "index.html").read_bytes(), "text/html; charset=utf-8")
        if url.path.startswith("/ui/"):
            f = (UI / url.path[4:]).resolve()
            if f.is_file() and UI in f.parents:
                return self._send(200, f.read_bytes(), mimetypes.guess_type(f.name)[0] or "application/octet-stream")
            return self._send(404, {"error": "not found"})
        m = re.fullmatch(r"/i18n/(\w+)\.json", url.path)
        if m and m.group(1) in LANGS:
            return self._send(200, (I18N_DIR / f"{m.group(1)}.json").read_bytes(), "application/json; charset=utf-8")
        if not self._token_ok(query):
            return self._send(401, {"error": "missing token"})
        if url.path == "/api/state":
            return self._send(200, SESSION.snapshot())
        if url.path == "/api/config":
            return self._send(200, {"operator": CONFIG.get("operator") or "", "contact": CONFIG.get("contact") or "",
                                    "version": pipeline.APP_VERSION})
        if url.path == "/api/history":
            return self._send(200, {"entries": pipeline.list_history()})
        m = re.fullmatch(r"/api/history/([\w-]+)", url.path)
        if m:
            entry = pipeline.get_history(m.group(1))
            return self._send(200, entry) if entry else self._send(404, {"error": "not found"})
        if url.path == "/api/support-log":
            text = SESSION.support_log(extra_secrets=[(TOKEN, "<token>")])
            headers = {}
            if query.get("download"):
                name = f"BugBane-support-log-{time.strftime('%Y%m%d-%H%M')}.txt"
                headers["Content-Disposition"] = f"attachment; filename*=UTF-8''{quote(name)}"
            return self._send(200, text, "text/plain; charset=utf-8", headers)
        if url.path == "/api/report":
            lang = query.get("lang", ["en"])[0]
            entry_id = query.get("id", [""])[0]
            results = pipeline.get_history(entry_id) if entry_id else SESSION.results
            if not results:
                return self._send(404, {"error": "no result"})
            html = render_report(results, lang if lang in LANGS else "en", pipeline.APP_VERSION)
            headers = {}
            if query.get("download"):
                name = f"BugBane-{'jelentes' if lang == 'hu' else 'report'}-{results['finished']}.html"
                headers["Content-Disposition"] = f"attachment; filename*=UTF-8''{quote(name)}"
            return self._send(200, html, "text/html; charset=utf-8", headers)
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        url = urlsplit(self.path)
        if not self._host_ok() or not self._token_ok({}):
            return self._send(403, {"error": "forbidden"})
        length = min(int(self.headers.get("Content-Length") or 0), 65536)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})
        if url.path == "/api/act":
            return self._send(200, SESSION.act(payload))
        if url.path == "/api/history/delete":
            return self._send(200, pipeline.delete_history(payload.get("id")))
        if url.path == "/api/history/erase_evidence":
            return self._send(200, pipeline.erase_history_evidence(payload.get("id")))
        if url.path == "/api/quit":
            self._send(200, {"ok": True})
            threading.Thread(target=shutdown, daemon=True).start()
            return
        return self._send(404, {"error": "not found"})


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self):
        # HTTPServer.server_bind does a reverse-DNS lookup (getfqdn) that can hang for
        # a long time on some Macs; localhost needs no name.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "127.0.0.1", self.server_address[1]


def shutdown():
    SESSION.shutdown()  # restores backup encryption if we changed it, erases unkept data
    for f in ("server.pid", "url.txt"):
        (RUN / f).unlink(missing_ok=True)
    os._exit(0)


def main():
    global SESSION
    RUN.mkdir(parents=True, exist_ok=True)
    pipeline.sweep_leftovers()
    SESSION = pipeline.ScanSession()
    threading.Thread(target=pipeline.on_launch, daemon=True).start()  # updates and fresh threat lists
    try:
        httpd = LocalServer(("127.0.0.1", PREFERRED_PORT), Handler)
    except OSError:  # preferred port busy: take any free one
        httpd = LocalServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    url = f"http://127.0.0.1:{port}/?t={TOKEN}"
    if "--demo" in sys.argv:  # open straight onto a saved History entry (testing, screenshots)
        entry_id = sys.argv[sys.argv.index("--demo") + 1]
        if pipeline.get_history(entry_id):
            url += f"&demo={entry_id}"
    (RUN / "server.pid").write_text(str(os.getpid()))
    (RUN / "url.txt").write_text(url)
    os.chmod(RUN / "url.txt", 0o600)
    signal.signal(signal.SIGTERM, lambda *_: shutdown())
    print(f"BugBane running at {url}", flush=True)
    if "--no-browser" not in sys.argv:
        webbrowser.open(url)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
