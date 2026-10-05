"""Structured event log shared by every process of a run.

Each line is one JSON object. Common fields: ts (wall-clock seconds, the common
time base of a run), tm (monotonic seconds of the writing process), ev (event
type), run, seed, pol (policy key), cfg (configuration identifier), and proc.
Event-specific fields use the same short names everywhere: dev (device), iss
(issuer), cred (source credential), tok (token), sess (session), dom (domain),
evd (status evidence reference), dec (decision), why (reason), out (outcome).
"""
import json
import threading
import time


class EventLog:
    def __init__(self, path: str, config: dict, proc: str, domain: str | None = None):
        self._file = open(path, "a", encoding="utf-8", buffering=1)
        self._lock = threading.Lock()
        self._common = {"run": config["run_id"], "seed": config["seed"], "pol": config["policy"]["key"],
                        "cfg": config["config_id"], "proc": proc}
        if domain:
            self._common["dom"] = domain

    def __call__(self, ev: str, **fields) -> None:
        record = {"ts": time.time(), "tm": time.monotonic(), "ev": ev}
        record.update(self._common)
        record.update({k: v for k, v in fields.items() if v is not None})
        line = json.dumps(record, separators=(",", ":"))
        with self._lock:
            self._file.write(line + "\n")

    def close(self) -> None:
        with self._lock:
            self._file.close()


def read_events(paths: list) -> list:
    """Load and time-order the events of a run."""
    events = []
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    events.sort(key=lambda e: e["ts"])
    return events
