"""Local HTTP helpers and the network shim.

All components run on one machine, so wide-area conditions are injected in
software: a configured round-trip time is added to every call that crosses the
backhaul between an edge domain and an issuer, and calls made during a scheduled
outage of that domain fail after a timeout. Traffic volume is counted from the
request and response bodies of those calls.
"""
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OUTAGE_TIMEOUT = 1.0


class LinkDown(Exception):
    """Raised when a backhaul call is attempted during an outage."""


class Links:
    """Backhaul state of each domain derived from the scheduled outage windows."""

    def __init__(self, config: dict):
        self.t0 = config["t0"]
        self.rtt = config["rtt_ms"] / 1000.0
        self.outages = config["outages"]
        self.bytes = {}
        self.calls = {}
        self._lock = threading.Lock()

    def up(self, domain: str, wall: float | None = None) -> bool:
        t = (time.time() if wall is None else wall) - self.t0
        return not any(o["start"] <= t < o["end"] and domain in o["domains"] for o in self.outages)

    def count(self, category: str, size: int, ok: bool = True) -> None:
        with self._lock:
            self.bytes[category] = self.bytes.get(category, 0) + size
            key = category + ("" if ok else "_failed")
            self.calls[key] = self.calls.get(key, 0) + 1

    def call(self, domain: str, category: str, url: str, body: dict | None = None, timeout: float = 5.0):
        """Make a backhaul call on behalf of a domain, applying delay and outage."""
        if not self.up(domain):
            time.sleep(OUTAGE_TIMEOUT)
            self.count(category, 0, ok=False)
            raise LinkDown(domain)
        time.sleep(self.rtt / 2)
        result, size = http_json(url, body, timeout)
        time.sleep(self.rtt / 2)
        if not self.up(domain):
            self.count(category, 0, ok=False)
            raise LinkDown(domain)
        self.count(category, size)
        return result


def http_json(url: str, body: dict | None = None, timeout: float = 5.0):
    """POST a JSON body (or GET when body is None); return (parsed response, bytes exchanged)."""
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, headers={"content-type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read()
    return json.loads(raw), len(raw) + (len(data) if data else 0)


def serve(port: int, routes: dict) -> ThreadingHTTPServer:
    """Start a threaded JSON server. routes maps a path to a function of the request body."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def _run(self):
            length = int(self.headers.get("content-length") or 0)
            body = json.loads(self.rfile.read(length)) if length else {}
            handler = routes.get(self.path.split("?")[0])
            try:
                status, payload = (404, {"error": "unknown route"}) if handler is None else (200, handler(body))
            except Exception as exc:
                status, payload = 500, {"error": f"{type(exc).__name__}: {exc}"}
            raw = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        do_GET = _run
        do_POST = _run

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def wait_http(url: str, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            http_json(url, None, 1.0)
            return
        except (urllib.error.URLError, OSError, ValueError):
            time.sleep(0.1)
    raise RuntimeError(f"service did not start: {url}")
