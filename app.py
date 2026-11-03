"""
ImmuneIoT - Flask Backend
Receives sensor data from ESP32 devices over HTTP, runs rule-based
anomaly detection, maintains a trust score per device, remembers attack
patterns (immune memory), and exposes /status for the dashboard.

Run with: python app.py
Server runs on http://0.0.0.0:5000
"""

import json
import os
import time
from collections import deque

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
CORS(app)  # allow the dashboard (served separately) to call this API

# ---------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------
devices = {}
HISTORY_LEN = 20

# ---------------------------------------------------------------
# Immune memory
# ---------------------------------------------------------------
MEMORY_FILE = os.path.join(BASE_DIR, "attack_memory.json")
MEMORY_TRUST_CAP = 10     # known attack: trust is forced down to this
EPISODE_RESET = 5         # clean readings in a row that end an attack episode

attack_memory = {}        # signature -> info about the first time we saw it
isolations = []           # history of quarantines, used for the demo and report


def load_memory():
    global attack_memory
    try:
        with open(MEMORY_FILE) as f:
            attack_memory = json.load(f)
    except (OSError, ValueError):
        attack_memory = {}


def save_memory():
    with open(MEMORY_FILE, "w") as f:
        json.dump(attack_memory, f, indent=2)


load_memory()

# ---------------------------------------------------------------
# Thresholds (tune these during testing based on your real sensor)
# ---------------------------------------------------------------
TEMP_MIN = 10
TEMP_MAX = 45          # anything above this is "impossible" for DHT11 in a room
MIN_MSG_INTERVAL = 1.0  # seconds; messages faster than this = suspicious
HUM_MIN, HUM_MAX = 5, 100
RSSI_MIN, RSSI_MAX = -100, -20   # dBm, WiFi signal strength
CHIP_MIN, CHIP_MAX = 10, 100     # ESP32 internal temperature
CHIP_MARGIN = 8                  # DHT11 may not exceed chip temp by more than this
MAX_IR_TOGGLES = 40              # IR flips per report; a hand can't do more
MAX_TEMP_JUMP = 6.0              # deg C between consecutive readings
PENALTY_JUMP_ANOMALY = 20
PENALTY_CROSS_CHECK = 15
PENALTY_SENSOR_MISSING = 10
PENALTY_VALUE_ANOMALY = 15
PENALTY_FREQUENCY_ANOMALY = 10
RECOVERY_RATE = 5        # trust score regained per normal reading (gradual climb)


def get_device(device_id):
    """Fetch or create a device record."""
    if device_id not in devices:
        devices[device_id] = {
            "trust_score": 100,
            "status": "TRUSTED",
            "last_seen": None,
            "history": deque(maxlen=HISTORY_LEN),
            "last_message_time": None,
            "episode_start": None,
            "episode_msgs": 0,
            "episode_sigs": set(),
            "mem_hit": False,
            "clean_streak": 0,
        }
    return devices[device_id]


def classify(trust_score):
    if trust_score >= 80:
        return "TRUSTED"
    elif trust_score >= 50:
        return "WARNING"
    else:
        return "QUARANTINED"


def make_signature(flags):
    """Fingerprint of an attack = sorted list of the rules that fired."""
    return "+".join(sorted(flags))


def record_isolation(device_id, device, now):
    """Called when a device enters QUARANTINED: log it and store its attack patterns."""
    start = device["episode_start"] or now
    kind = "memory hit" if device["mem_hit"] else "first exposure"
    entry = {"device": device_id, "kind": kind,
             "seconds": round(now - start, 2), "messages": device["episode_msgs"]}
    isolations.append(entry)
    for sig in device["episode_sigs"]:
        attack_memory.setdefault(sig, {
            "pattern": sig, "first_device": device_id,
            "first_seen": time.strftime("%H:%M:%S"),
            "seconds": entry["seconds"], "messages": entry["messages"], "hits": 0})
    save_memory()
    device["mem_hit"] = True   # stops this episode from triggering its own memory
    print(f"[IMMUNE] {device_id} isolated: {kind}, "
          f"{entry['messages']} message(s), {entry['seconds']} s")


@app.route("/data", methods=["POST"])
def receive_data():
    """
    Expected JSON body from ESP32:
    {
        "device_id": "esp32_01",
        "temperature": 27.5,
        "humidity": 60,       # optional
        "ir": 0               # optional, plus rssi / chip_temp / ir_toggles
    }
    """
    payload = request.get_json(force=True)
    device_id = payload.get("device_id", "unknown")
    temperature = payload.get("temperature")

    now = time.time()
    device = get_device(device_id)

    # ---- Rule 1: message frequency check ----
    anomaly_flags = []
    if device["last_message_time"] is not None:
        interval = now - device["last_message_time"]
        if interval < MIN_MSG_INTERVAL:
            anomaly_flags.append("HIGH_FREQUENCY")
            device["trust_score"] -= PENALTY_FREQUENCY_ANOMALY

    # ---- Rule 1b: sensor missing (DHT11 unplugged / failing) ----
    if temperature is None and payload.get("humidity") is None:
        anomaly_flags.append("SENSOR_MISSING")
        device["trust_score"] -= PENALTY_SENSOR_MISSING

    # ---- Rule 2: value range check (every field) ----
    ranges = {
        "temperature": (TEMP_MIN, TEMP_MAX),
        "humidity": (HUM_MIN, HUM_MAX),
        "rssi": (RSSI_MIN, RSSI_MAX),
        "chip_temp": (CHIP_MIN, CHIP_MAX),
        "ir_toggles": (0, MAX_IR_TOGGLES),
    }
    out_of_range = [k for k, (lo, hi) in ranges.items()
                    if payload.get(k) is not None and not lo <= payload[k] <= hi]
    if out_of_range:
        anomaly_flags.append("VALUE_OUT_OF_RANGE:" + ",".join(out_of_range))
        device["trust_score"] -= PENALTY_VALUE_ANOMALY

    prev = device["history"][-1] if device["history"] else None

    # ---- Rule 3: physically impossible rate of change ----
    if prev and not prev["anomalies"] and temperature is not None and prev.get("temperature") is not None:
        if abs(temperature - prev["temperature"]) > MAX_TEMP_JUMP and "temperature" not in " ".join(out_of_range):
            anomaly_flags.append("TEMP_JUMP")
            device["trust_score"] -= PENALTY_JUMP_ANOMALY

    # ---- Rule 4: cross-sensor check ----
    # room temperature (DHT11) cannot be hotter than the ESP32 chip itself
    chip = payload.get("chip_temp")
    if temperature is not None and chip is not None and temperature > chip + CHIP_MARGIN:
        anomaly_flags.append("SENSOR_MISMATCH")
        device["trust_score"] -= PENALTY_CROSS_CHECK

    # ---- Rule 5 (critical): impossible values arriving at flood rate = compromised device ----
    # Trust is zeroed immediately. This is a detection rule, not a manual override:
    # it only fires when BOTH the flood rule and the out-of-range rule have fired.
    if "HIGH_FREQUENCY" in anomaly_flags and any(f.startswith("VALUE_OUT_OF_RANGE") for f in anomaly_flags):
        anomaly_flags.append("CRITICAL_ATTACK")
        device["trust_score"] = 0

    # ---- Immune memory: have we seen this attack pattern before? ----
    memory_hit = False
    if anomaly_flags:
        device["clean_streak"] = 0
        if device["episode_start"] is None:
            device["episode_start"], device["episode_msgs"] = now, 0
        device["episode_msgs"] += 1
        sig = make_signature(anomaly_flags)
        device["episode_sigs"].add(sig)
        if sig in attack_memory and not device["mem_hit"]:
            device["mem_hit"] = memory_hit = True
            attack_memory[sig]["hits"] += 1
            save_memory()
            device["trust_score"] = min(device["trust_score"], MEMORY_TRUST_CAP)
            anomaly_flags.append("KNOWN_ATTACK")

    snapshot = {k: payload.get(k) for k in
                ("temperature", "humidity", "chip_temp", "rssi", "ir_toggles", "ir")}

    # ---- Recovery: reward normal behaviour ----
    if not anomaly_flags:
        device["clean_streak"] += 1
        if device["clean_streak"] >= EPISODE_RESET:
            device["episode_start"] = None
            device["episode_sigs"] = set()
            device["mem_hit"] = False
        device["trust_score"] = min(100, device["trust_score"] + RECOVERY_RATE)

    # clamp + classify
    device["trust_score"] = max(0, min(100, device["trust_score"]))
    old_status = device["status"]
    device["status"] = classify(device["trust_score"])
    if device["status"] == "QUARANTINED" and old_status != "QUARANTINED":
        record_isolation(device_id, device, now)

    device["last_seen"] = now
    device["last_message_time"] = now
    device["history"].append({
        "temperature": temperature,
        "snapshot": snapshot,
        "timestamp": now,
        "anomalies": anomaly_flags,
    })

    print(f"[{device_id}] {snapshot} trust={device['trust_score']} "
          f"status={device['status']} flags={anomaly_flags}")

    return jsonify({
        "device_id": device_id,
        "trust_score": device["trust_score"],
        "status": device["status"],
        "anomalies": anomaly_flags,
        "memory_hit": memory_hit,
    })


@app.route("/status", methods=["GET"])
def get_status():
    """Returns current status of all devices - polled by the dashboard."""
    result = []
    for device_id, d in devices.items():
        result.append({
            "device_id": device_id,
            "trust_score": d["trust_score"],
            "status": d["status"],
            "last_seen": d["last_seen"],
            "last_temperature": d["history"][-1]["temperature"] if d["history"] else None,
            "last_readings": d["history"][-1]["snapshot"] if d["history"] else None,
            "last_anomalies": d["history"][-1]["anomalies"] if d["history"] else [],
        })
    return jsonify(result)


@app.route("/memory", methods=["GET"])
def get_memory():
    return jsonify({"patterns": list(attack_memory.values()),
                    "isolations": isolations[-20:]})


@app.route("/memory/clear", methods=["POST"])
def clear_memory():
    attack_memory.clear()
    isolations.clear()
    save_memory()
    return jsonify({"cleared": True})


@app.route("/dashboard", methods=["GET"])
def dashboard():
    return send_from_directory(BASE_DIR, "dashboard.html")


@app.route("/", methods=["GET"])
def home():
    return "ImmuneIoT backend running. POST sensor data to /data, GET status from /status."


if __name__ == "__main__":
    # host 0.0.0.0 so ESP32 on the same WiFi network can reach this machine's IP
    app.run(host="0.0.0.0", port=5000, debug=True)