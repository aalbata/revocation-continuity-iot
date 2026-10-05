"""Mosquitto broker instances and their Dynamic Security administration.

Each edge domain runs its own broker process. Authorization state is held by
the Dynamic Security plugin and is changed at run time through the
$CONTROL/dynamic-security/v1 topic, so a session can be created, limited to one
command topic, and removed while the broker keeps running.
"""
import json
import os
import shutil
import subprocess
import threading
import time

import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion

CONTROL = "$CONTROL/dynamic-security/v1"


def mosquitto_home() -> str:
    """Return the folder that holds mosquitto.exe and the Dynamic Security plugin."""
    configured = os.environ.get("MOSQUITTO_DIR")
    if configured:
        return configured
    exe = shutil.which("mosquitto")
    if not exe:
        raise RuntimeError("mosquitto was not found; set MOSQUITTO_DIR")
    folder = os.path.dirname(os.path.realpath(exe))
    if not os.path.exists(os.path.join(folder, "mosquitto_dynamic_security.dll")):
        scoop = os.path.join(os.path.expanduser("~"), "scoop", "apps", "mosquitto", "current")
        if os.path.exists(os.path.join(scoop, "mosquitto_dynamic_security.dll")):
            return scoop
    return folder


def start_broker(workdir: str, port: int, admin_password: str) -> subprocess.Popen:
    """Write the configuration, initialise Dynamic Security, and start a broker process."""
    home = mosquitto_home()
    os.makedirs(workdir, exist_ok=True)
    dynsec = os.path.join(workdir, "dynsec.json").replace("\\", "/")
    if os.path.exists(dynsec):
        os.remove(dynsec)
    subprocess.run([os.path.join(home, "mosquitto_ctrl"), "dynsec", "init", dynsec, "admin", admin_password],
                   check=True, capture_output=True, timeout=30)
    plugin = os.path.join(home, "mosquitto_dynamic_security.dll").replace("\\", "/")
    conf = os.path.join(workdir, "mosquitto.conf")
    with open(conf, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(f"listener {port} 127.0.0.1\nallow_anonymous false\npersistence false\n"
                     f"retain_available false\nmax_queued_messages 1000\n"
                     f"plugin {plugin}\nplugin_opt_config_file {dynsec}\n")
    log = open(os.path.join(workdir, "mosquitto.log"), "w", encoding="utf-8")
    process = subprocess.Popen([os.path.join(home, "mosquitto"), "-c", conf], stdout=log, stderr=log)
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            probe = mqtt.Client(CallbackAPIVersion.VERSION2, client_id=f"probe-{port}", protocol=mqtt.MQTTv5)
            probe.username_pw_set("admin", admin_password)
            probe.connect("127.0.0.1", port)
            probe.disconnect()
            return process
        except OSError:
            time.sleep(0.1)
    process.kill()
    raise RuntimeError(f"broker on port {port} did not start")


class DynsecAdmin:
    """Synchronous client for Dynamic Security commands."""

    def __init__(self, port: int, admin_password: str, name: str = "admin"):
        self._lock = threading.Lock()
        self._responses = {}
        self._events = {}
        self._counter = 0
        self._ready = threading.Event()
        self.client = mqtt.Client(CallbackAPIVersion.VERSION2, client_id=f"dynsec-{name}-{port}", protocol=mqtt.MQTTv5)
        self.client.username_pw_set("admin", admin_password)
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.connect("127.0.0.1", port)
        self.client.loop_start()
        if not self._ready.wait(10):
            raise RuntimeError("dynamic security admin could not subscribe")

    def _on_connect(self, client, userdata, flags, reason_code, properties):
        client.subscribe(CONTROL + "/response", qos=1)
        self._ready.set()

    def _on_message(self, client, userdata, message):
        for item in json.loads(message.payload).get("responses", []):
            tag = item.get("correlationData")
            if tag in self._events:
                self._responses[tag] = item
                self._events[tag].set()

    def command(self, body: dict, timeout: float = 5.0) -> dict:
        """Send one command and wait for its response."""
        with self._lock:
            self._counter += 1
            tag = f"c{self._counter}"
        event = threading.Event()
        self._events[tag] = event
        self.client.publish(CONTROL, json.dumps({"commands": [dict(body, correlationData=tag)]}), qos=1)
        if not event.wait(timeout):
            self._events.pop(tag, None)
            raise TimeoutError(f"no response to {body.get('command')}")
        self._events.pop(tag, None)
        return self._responses.pop(tag)

    def create_role(self, role: str, acls: list) -> dict:
        return self.command({"command": "createRole", "rolename": role, "acls": acls})

    def create_client(self, username: str, password: str, role: str) -> dict:
        return self.command({"command": "createClient", "username": username, "password": password,
                             "roles": [{"rolename": role, "priority": 1}]})

    def delete_client(self, username: str) -> dict:
        return self.command({"command": "deleteClient", "username": username})

    def list_clients(self) -> list:
        data = self.command({"command": "listClients", "count": -1, "offset": 0}).get("data", {})
        return data.get("clients", [])

    def close(self) -> None:
        self.client.loop_stop()
        self.client.disconnect()
