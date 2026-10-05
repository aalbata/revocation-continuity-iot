"""Run one live world: brokers, issuers, edge domains, devices, and the scripted events.

A world is one independent run of one policy on one trace. Every component is a
native local process. The controller in this module starts them, replays the
control events of the trace at their scheduled times, samples process memory,
and stops everything at the end of the observation window.
"""
import hashlib
import json
import os
import subprocess
import sys
import threading
import time

import psutil

from . import tokens
from .broker import DynsecAdmin, start_broker
from .issuer import list_id
from .net import http_json, wait_http
from .policy import get as get_policy
from .trace import DOMAINS, scenario

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ISSUERS = {"issuer-a": "contractor", "issuer-b": "operator"}
RESTART_DOWNTIME = 1.0


def build_config(run_dir: str, seed: int, policy_key: str, outage: float = 0.0, budget: float = 30.0,
                 rtt_ms: float = 50.0, devices: int = 10, stack: str = "node", failure: str = "shared",
                 slot: int = 0, node_port: int = 0, overrides: dict | None = None, skew: float = 0.0,
                 clock_uncertainty: float = 0.0, config_id: str = "") -> dict:
    """Assemble the full configuration of a run. The trace depends on the seed and world settings only."""
    base = 21000 + slot * 40
    trace = scenario(seed, devices, outage, budget, failure)
    policy = get_policy(policy_key, **(overrides or {}))

    def secret(label: str) -> str:
        return hashlib.sha256(f"{seed}:{label}".encode()).hexdigest()

    issuers = {}
    for index, (name, organization) in enumerate(ISSUERS.items()):
        host = f"{name}.rcbench.test"
        issuers[name] = {"did": f"did:web:{host}", "host": host, "port": base + index,
                         "organization": organization, "seed": secret(name),
                         "lists": {p: list_id(host, p) for p in ("revocation", "suspension")}}
    domains = {}
    for index, name in enumerate(DOMAINS):
        key = tokens.private_key(bytes.fromhex(secret("domain:" + name)))
        domains[name] = {"gateway_port": base + 10 + index, "broker_port": base + 20 + index,
                         "seed": secret("domain:" + name), "public": tokens.public_raw(key).hex(),
                         "admin_pw": secret("admin:" + name)[:24], "executor_pw": secret("executor:" + name)[:24],
                         "skew": skew if name == "provider" else 0.0}
    return {"run_id": os.path.basename(run_dir), "seed": seed, "config_id": config_id, "dir": run_dir.replace("\\", "/"),
            "policy": policy.to_dict(), "budget": budget, "rtt_ms": rtt_ms, "stack": stack, "failure": failure,
            "outage": outage, "node_port": node_port or base + 30, "issuers": issuers, "domains": domains,
            "devices": trace["devices"], "events": trace["events"], "outages": trace["outages"],
            "horizon": trace["horizon"], "rate_hz": 2.0, "list_validity": 300.0, "credential_validity": 86400.0,
            "clock_uncertainty": clock_uncertainty, "t0": 0.0}


def _spawn(module: str, args: list, log_path: str) -> subprocess.Popen:
    log = open(log_path, "a", encoding="utf-8")
    return subprocess.Popen([sys.executable, "-m", module] + args, cwd=ROOT, stdout=log, stderr=log)


def start_node_verifier(port: int, log_path: str) -> subprocess.Popen:
    log = open(log_path, "a", encoding="utf-8")
    process = subprocess.Popen(["node", os.path.join(ROOT, "node_verifier", "server.mjs"), str(port)],
                               cwd=ROOT, stdout=log, stderr=log)
    wait_http(f"http://127.0.0.1:{port}/health", 40.0)
    return process


def _tree(process: subprocess.Popen) -> list:
    """The process and its descendants; a virtual-environment launcher runs the interpreter as a child."""
    try:
        parent = psutil.Process(process.pid)
        return [parent] + parent.children(recursive=True)
    except psutil.Error:
        return []


def _kill(process: subprocess.Popen) -> None:
    for item in reversed(_tree(process)):
        try:
            item.kill()
        except psutil.Error:
            pass


def _rss(process: subprocess.Popen) -> int:
    total = 0
    for item in _tree(process):
        try:
            total += item.memory_info().rss
        except psutil.Error:
            pass
    return total


def run_world(config: dict, own_node: bool = True) -> dict:
    """Execute a run and return a short record of what happened."""
    run_dir = config["dir"]
    os.makedirs(run_dir, exist_ok=True)
    processes, brokers, record = {}, [], {"failed": False, "errors": []}
    lead = 12.0 + 0.06 * len(config["devices"])
    config["t0"] = time.time() + lead
    cfg_path = os.path.join(run_dir, "config.json")
    try:
        for name, settings in config["domains"].items():
            brokers.append(start_broker(os.path.join(run_dir, "broker-" + name), settings["broker_port"],
                                        settings["admin_pw"]))
            admin = DynsecAdmin(settings["broker_port"], settings["admin_pw"], "setup")
            admin.create_role("executor", [
                {"acltype": "subscribePattern", "topic": f"rc/{name}/cmd/#", "allow": True},
                {"acltype": "publishClientReceive", "topic": f"rc/{name}/cmd/#", "allow": True}])
            admin.create_client("executor", settings["executor_pw"], "executor")
            admin.close()
        with open(cfg_path, "w", encoding="utf-8") as handle:
            json.dump(config, handle)
        processes["issuers"] = _spawn("rcbench.issuer", [cfg_path], os.path.join(run_dir, "proc.issuers.log"))
        for settings in config["issuers"].values():
            wait_http(f"http://127.0.0.1:{settings['port']}/health")
            settings["document"] = http_json(f"http://127.0.0.1:{settings['port']}/.well-known/did.json")[0]
        with open(cfg_path, "w", encoding="utf-8") as handle:
            json.dump(config, handle)
        if config["stack"] == "node" and own_node:
            processes["node"] = start_node_verifier(config["node_port"], os.path.join(run_dir, "proc.node.log"))
        for name, settings in config["domains"].items():
            processes[name] = _spawn("rcbench.domain", [cfg_path, name], os.path.join(run_dir, f"proc.{name}.log"))
        for settings in config["domains"].values():
            wait_http(f"http://127.0.0.1:{settings['gateway_port']}/health")
        processes["devices"] = _spawn("rcbench.devices", [cfg_path], os.path.join(run_dir, "proc.devices.log"))
        if time.time() > config["t0"] - 1.0:
            record["errors"].append("startup exceeded the lead time")

        memory = {}
        stop = threading.Event()

        def sample():
            while not stop.is_set():
                for name, process in list(processes.items()):
                    memory[name] = max(memory.get(name, 0), _rss(process))
                for index, broker in enumerate(brokers):
                    memory[f"broker{index}"] = max(memory.get(f"broker{index}", 0), _rss(broker))
                stop.wait(2.0)

        threading.Thread(target=sample, daemon=True).start()
        record["startup_margin"] = config["t0"] - time.time()
        record["control"] = []
        for event in config["events"]:
            delay = config["t0"] + event["t"] - time.time()
            if delay > 0:
                time.sleep(delay)
            record["control"].append({"type": event["type"], "planned": event["t"],
                                      "actual": time.time() - config["t0"]})
            if event["type"] == "change":
                port = config["issuers"][event["issuer"]]["port"]
                body = {"action": event["action"], "device": event["device"], "push_jitter": 0.3}
                http_json(f"http://127.0.0.1:{port}/control/change", body)
            elif event["type"] == "rotate":
                http_json(f"http://127.0.0.1:{config['issuers'][event['issuer']]['port']}/control/rotate", {})
            elif event["type"] == "restart":
                name = event["domain"]
                _kill(processes[name])
                processes[name].wait(10)
                time.sleep(RESTART_DOWNTIME)
                processes[name] = _spawn("rcbench.domain", [cfg_path, name, "restarted"],
                                         os.path.join(run_dir, f"proc.{name}.log"))
        remaining = config["t0"] + config["horizon"] + 4.0 - time.time()
        if remaining > 0:
            time.sleep(remaining)
        stop.set()
        for name in ("devices", "issuers") + tuple(DOMAINS):
            try:
                processes[name].wait(8)
            except subprocess.TimeoutExpired:
                record["errors"].append(f"{name} did not exit")
        record["memory_bytes"] = memory
    except Exception as exc:
        record["failed"] = True
        record["errors"].append(f"{type(exc).__name__}: {exc}")
    finally:
        for process in list(processes.values()) + brokers:
            _kill(process)
        for process in list(processes.values()) + brokers:
            try:
                process.wait(10)
            except subprocess.TimeoutExpired:
                pass
    with open(os.path.join(run_dir, "record.json"), "w", encoding="utf-8") as handle:
        json.dump(record, handle)
    return record


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run one live world")
    parser.add_argument("--out", required=True)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--policy", default="profile")
    parser.add_argument("--outage", type=float, default=0.0)
    parser.add_argument("--budget", type=float, default=30.0)
    parser.add_argument("--rtt", type=float, default=50.0)
    parser.add_argument("--devices", type=int, default=10)
    parser.add_argument("--stack", default="node")
    parser.add_argument("--failure", default="shared")
    a = parser.parse_args()
    cfg = build_config(os.path.abspath(a.out), a.seed, a.policy, a.outage, a.budget, a.rtt, a.devices, a.stack,
                       a.failure)
    print(json.dumps(run_world(cfg)))
