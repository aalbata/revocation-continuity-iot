"""Device agents.

One process hosts every logical device of a run. Each device holds a did:key
holder key and one credential, obtains a local token from its current edge
domain, keeps an MQTT session on that domain's broker, and publishes one command
per period. All devices use the same recovery logic when a session is lost.
Devices marked adversarial additionally keep the newest status list that still
shows them as valid, keep earlier sessions open, and probe bypass paths.

Usage: python -m rcbench.devices <config.json>
"""
import base64
import json
import os
import random
import sys
import threading
import time

import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.properties import Properties

from . import di, vc
from .events import EventLog
from .net import Links, http_json
from .statuslist import Evidence

MAINTAIN = 0.25
RETRY = 1.0
LIST_REFRESH = 2.0
PROBE = 5.0


def unverified_claims(token: str) -> dict:
    body = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


class Session:
    """An MQTT connection made with credentials issued by a gateway."""

    def __init__(self, device, domain: str, grant: dict):
        self.device, self.domain = device, domain
        self.token, self.topic = grant["token"], grant["topic"]
        self.claims = unverified_claims(self.token)
        self.username, self.password = grant["username"], grant["password"]
        self.connected = threading.Event()
        self.refused = False
        self.pending = {}
        self.client = None

    def connect(self, wait: float = 2.0) -> bool:
        port = self.device.config["domains"][self.domain]["broker_port"]
        client = mqtt.Client(CallbackAPIVersion.VERSION2, protocol=mqtt.MQTTv5,
                             client_id=f"{self.device.id}-{self.username}-{random.getrandbits(24):06x}")
        client.username_pw_set(self.username, self.password)
        client.on_connect = self._on_connect
        client.on_disconnect = self._on_disconnect
        client.on_publish = self._on_publish
        self.connected.clear()
        self.refused = False
        try:
            client.connect("127.0.0.1", port)
        except OSError:
            return False
        client.loop_start()
        self.client = client
        deadline = time.time() + wait
        while time.time() < deadline and not self.connected.is_set() and not self.refused:
            time.sleep(0.02)
        if not self.connected.is_set():
            self.close()
            return False
        return True

    def _on_connect(self, client, userdata, flags, reason_code, properties):
        if reason_code.is_failure:
            self.refused = True
        else:
            self.connected.set()

    def _on_disconnect(self, client, userdata, flags, reason_code, properties):
        self.connected.clear()

    def _on_publish(self, client, userdata, mid, reason_code, properties):
        info = self.pending.pop(mid, None)
        if info is not None and reason_code.is_failure:
            self.device.log("puback_denied", dev=self.device.id, n=info[0], kind=info[1], dom=self.domain,
                            why=str(reason_code))

    def publish(self, n: int, kind: str, topic: str | None = None) -> bool:
        if not self.connected.is_set():
            return False
        props = Properties(PacketTypes.PUBLISH)
        props.UserProperty = ("token", self.token)
        payload = json.dumps({"dev": self.device.id, "n": n, "sent": time.time(), "sp": time.perf_counter(),
                              "kind": kind})
        info = self.client.publish(topic or self.topic, payload, qos=1, properties=props)
        self.pending[info.mid] = (n, kind)
        return info.rc == mqtt.MQTT_ERR_SUCCESS

    def close(self) -> None:
        if self.client is not None:
            self.client.loop_stop()
            try:
                self.client.disconnect()
            except Exception:
                pass
            self.client = None
        self.connected.clear()


class Device:
    def __init__(self, spec: dict, config: dict, links: Links, log: EventLog):
        self.spec, self.config, self.links, self.log = spec, config, links, log
        self.id = spec["id"]
        self.issuer = config["issuers"][spec["issuer"]]
        self.key = di.did_key_from_seed(bytes.fromhex(spec["seed"]))
        self.random = random.Random(int(spec["seed"][:12], 16))
        self.domain = spec["home"]
        self.session = None
        self.old_sessions = []
        self.lists = []
        self.credential = None
        self.script = sorted(spec.get("script", []), key=lambda e: e["t"])
        self.lock = threading.Lock()
        self.last_attempt = 0.0
        self.last_lists = 0.0
        self.last_probe = 0.0
        self.tried_reconnect = False
        self.count = 0

    # ---- requests to issuers and gateways --------------------------------

    def obtain_credential(self) -> None:
        url = f"http://127.0.0.1:{self.issuer['port']}/control/issue"
        self.credential = http_json(url, {"holder": self.key.controller, "device": self.id})[0]["credential"]
        self.refresh_lists(force=True)

    def refresh_lists(self, force: bool = False) -> None:
        """Fetch the issuer's lists through the current domain's backhaul when it is up."""
        if not force and (time.time() - self.last_lists < LIST_REFRESH or not self.links.up(self.domain)):
            return
        self.last_lists = time.time()
        try:
            time.sleep(self.links.rtt if not force else 0.0)
            lists = http_json(f"http://127.0.0.1:{self.issuer['port']}/status")[0]["lists"]
        except OSError:
            return
        if self.spec.get("adversarial") and self.lists:
            entries = {e["statusListCredential"]: e for e in self.credential["credentialStatus"]}
            kept = []
            for old, new in zip(self.lists, lists):
                flagged = Evidence(new, time.time()).status(entries[new["id"]])
                kept.append(old if flagged else new)
            lists = kept
        self.lists = lists

    def _gateway(self, domain: str, route: str, body: dict | None):
        port = self.config["domains"][domain]["gateway_port"]
        return http_json(f"http://127.0.0.1:{port}{route}", body, 15.0)[0]

    def _request(self, kind: str, domain: str, build) -> dict:
        start = time.time()
        try:
            challenge = self._gateway(domain, "/challenge", None)
            grant = self._gateway(domain, "/" + kind, build(challenge))
        except OSError:
            grant = {"granted": False, "reason": "gateway_unreachable"}
        self.log("request", dev=self.id, kind=kind, dom=domain, ms=(time.time() - start) * 1000.0,
                 dec="allow" if grant.get("granted") else "deny", why=grant.get("reason", "ok"))
        return grant

    def _signature(self, challenge: dict, token: str) -> str:
        message = f"{challenge['challenge']}|{unverified_claims(token)['jti']}".encode()
        return di.b58encode(self.key.signing_key.sign(message).signature)

    def present(self, domain: str) -> dict:
        def build(challenge):
            unsigned = vc.presentation(self.key.controller, [self.credential])
            signed = di.add_proof(unsigned, self.key, "authentication", time.time(),
                                  challenge["challenge"], challenge["domain"])
            return {"presentation": signed, "stapled": self.lists}
        return self._request("present", domain, build)

    def renew(self) -> dict:
        token = self.session.token
        return self._request("renew", self.domain, lambda c: {
            "token": token, "challenge": c["challenge"], "signature": self._signature(c, token),
            "stapled": self.lists})

    def exchange(self, source: str, target: str, token: str) -> dict:
        return self._request("handover", target, lambda c: {
            "from": source, "token": token, "challenge": c["challenge"],
            "signature": self._signature(c, token), "stapled": self.lists})

    # ---- session management ----------------------------------------------

    def _adopt(self, domain: str, grant: dict) -> bool:
        session = Session(self, domain, grant)
        if not session.connect():
            self.log("connect", dev=self.id, dom=domain, dec="deny", why="broker_refused")
            return False
        with self.lock:
            previous, self.session, self.domain = self.session, session, domain
        if previous is not None and previous is not session:
            if self.spec.get("adversarial") and previous.domain != domain:
                self.old_sessions.append(previous)
            else:
                previous.close()
        self.tried_reconnect = False
        return True

    def recover(self) -> None:
        """Regain a session: reconnect with existing broker credentials, then renew, then present."""
        session = self.session
        now = time.time()
        if session is not None and session.domain == self.domain:
            if not self.tried_reconnect:
                self.tried_reconnect = True
                ok = session.connect()
                self.log("connect", dev=self.id, dom=self.domain, kind="reconnect",
                         dec="allow" if ok else "deny", why="ok" if ok else "broker_refused")
                if ok:
                    return
            if now < session.claims["exp"]:
                grant = self.renew()
                if grant.get("granted"):
                    session.token, session.claims = grant["token"], unverified_claims(grant["token"])
                    if session.connect():
                        self.tried_reconnect = False
                        return
        grant = self.present(self.domain)
        if grant.get("granted"):
            self._adopt(self.domain, grant)

    def handover(self, target: str) -> None:
        source, session = self.domain, self.session
        self.log("handover_start", dev=self.id, dom=target, src=source)
        grant = {"granted": False}
        if session is not None and session.domain == source:
            grant = self.exchange(source, target, session.token)
        if not grant.get("granted"):
            grant = self.present(target)
        if grant.get("granted") and self._adopt(target, grant):
            return
        with self.lock:
            previous, self.session, self.domain = self.session, None, target
        if previous is not None:
            if self.spec.get("adversarial"):
                self.old_sessions.append(previous)
            else:
                previous.close()

    def maintain(self) -> None:
        now = time.time()
        rel = now - self.config["t0"]
        while self.script and self.script[0]["t"] <= rel:
            event = self.script.pop(0)
            if event["type"] == "handover":
                self.handover(event["to"])
        self.refresh_lists()
        session = self.session
        if session is None or not session.connected.is_set():
            if now - self.last_attempt >= RETRY:
                self.last_attempt = now
                self.recover()
        else:
            remaining = session.claims["exp"] - now
            lifetime = session.claims["exp"] - session.claims["iat"]
            if remaining < max(2.0, 0.2 * lifetime) and now - self.last_attempt >= RETRY:
                self.last_attempt = now
                grant = self.renew()
                if grant.get("granted"):
                    session.token, session.claims = grant["token"], unverified_claims(grant["token"])
        if self.spec.get("adversarial") and now - self.last_probe >= PROBE and rel >= 0:
            self.last_probe = now
            self.probe()

    def _number(self) -> int:
        """Next command number; the publish loop and the probes run in different threads."""
        with self.lock:
            self.count += 1
            return self.count

    def probe(self) -> None:
        """Bypass attempts: another device's topic on the current session, and earlier sessions."""
        session = self.session
        if session is not None and session.connected.is_set():
            n = self._number()
            session.publish(n, "alt_topic", f"rc/{session.domain}/cmd/{self.spec['other']}")
            self.log("send", dev=self.id, n=n, kind="alt_topic", dom=session.domain,
                     tok=session.claims["jti"], out="published")
        for old in self.old_sessions:
            if not old.connected.is_set():
                old.connect(1.0)
            n = self._number()
            sent = old.publish(n, "old_session")
            self.log("send", dev=self.id, n=n, kind="old_session", dom=old.domain,
                     tok=old.claims["jti"], out="published" if sent else "no_session")

    def publish(self) -> None:
        n = self._number()
        session = self.session
        sent = session is not None and session.publish(n, "command")
        self.log("send", dev=self.id, n=n, kind="command", dom=self.domain,
                 tok=session.claims["jti"] if session else None, out="published" if sent else "no_session")

    # ---- threads ---------------------------------------------------------

    def start(self) -> None:
        threading.Thread(target=self._maintenance_loop, daemon=True).start()
        threading.Thread(target=self._publish_loop, daemon=True).start()

    def _maintenance_loop(self) -> None:
        end = self.config["t0"] + self.config["horizon"]
        grant = self.present(self.domain)
        if grant.get("granted"):
            self._adopt(self.domain, grant)
        while time.time() < end:
            try:
                self.maintain()
            except Exception as exc:
                self.log("error", dev=self.id, why=f"{type(exc).__name__}: {exc}")
            time.sleep(MAINTAIN)

    def _publish_loop(self) -> None:
        t0, period = self.config["t0"], 1.0 / self.config["rate_hz"]
        phase = self.random.uniform(0.0, period)
        k = 0
        while True:
            target = t0 + phase + k * period
            if target >= t0 + self.config["horizon"]:
                return
            delay = target - time.time()
            if delay > 0:
                time.sleep(delay)
            self.publish()
            k += 1


def main(path: str) -> None:
    with open(path, encoding="utf-8") as handle:
        config = json.load(handle)
    log = EventLog(f"{config['dir']}/events.devices.jsonl", config, "devices")
    links = Links(config)
    devices = [Device(spec, config, links, log) for spec in config["devices"]]
    for device in devices:
        device.obtain_credential()
        log("credential", dev=device.id, cred=device.credential["id"], iss=device.issuer["did"],
            role=device.spec["role"], adversarial=bool(device.spec.get("adversarial")))
    for device in devices:
        device.start()
        time.sleep(0.02)
    while time.time() < config["t0"] + config["horizon"] + 1.0:
        time.sleep(0.5)
    log.close()
    os._exit(0)


if __name__ == "__main__":
    main(sys.argv[1])
