"""
ImmuneIoT - Flask Backend
Receives sensor data from ESP32 devices over HTTP, runs rule-based
anomaly detection, maintains a trust score per device, and exposes
a /status endpoint for the dashboard.

Run with: python app.py
Server runs on http://0.0.0.0:5000
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import time
from collections import deque

app = Flask(__name__)
CORS(app)  # allow the dashboard (served separately) to call this API

# ---------------------------------------------------------------
# In-memory store (no DB tonight — swap for MySQL later if needed)
# ---------------------------------------------------------------
# devices = {
#   "esp32_01": {
#       "trust_score": 100,
#       "status": "TRUSTED",
#       "last_seen": <timestamp>,
#       "history": deque of last N readings,
#       "last_message_time": <timestamp>  # used for frequency check
#   }
# }
devices = {}
HISTORY_LEN = 20

# ---------------------------------------------------------------
# Thresholds (tune these during testing based on your real sensor)
# ---------------------------------------------------------------
TEMP_MIN = 10
TEMP_MAX = 45          # anything above this is "impossible" for DHT11 in a room
MIN_MSG_INTERVAL = 1.0  # seconds; messages faster than this = suspicious
PENALTY_VALUE_ANOMALY = 30
PENALTY_FREQUENCY_ANOMALY = 25
RECOVERY_RATE = 2        # trust score regained per normal reading


def get_device(device_id):
    """Fetch or create a device record."""
    if device_id not in devices:
        devices[device_id] = {
            "trust_score": 100,
            "status": "TRUSTED",
            "last_seen": None,
            "history": deque(maxlen=HISTORY_LEN),
            "last_message_time": None,
        }
    return devices[device_id]


def classify(trust_score):
    if trust_score >= 80:
        return "TRUSTED"
    elif trust_score >= 50:
        return "WARNING"
    else:
        return "QUARANTINED"


@app.route("/data", methods=["POST"])
def receive_data():
    """
    Expected JSON body from ESP32:
    {
        "device_id": "esp32_01",
        "temperature": 27.5,
        "humidity": 60,       # optional
        "motion": 0           # optional
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

    # ---- Rule 2: value range check ----
    if temperature is not None:
        if temperature < TEMP_MIN or temperature > TEMP_MAX:
            anomaly_flags.append("VALUE_OUT_OF_RANGE")
            device["trust_score"] -= PENALTY_VALUE_ANOMALY

    # ---- Recovery: reward normal behaviour ----
    if not anomaly_flags:
        device["trust_score"] = min(100, device["trust_score"] + RECOVERY_RATE)

    # clamp
    device["trust_score"] = max(0, min(100, device["trust_score"]))
    device["status"] = classify(device["trust_score"])
    device["last_seen"] = now
    device["last_message_time"] = now
    device["history"].append({
        "temperature": temperature,
        "timestamp": now,
        "anomalies": anomaly_flags,
    })

    print(f"[{device_id}] temp={temperature} trust={device['trust_score']} "
          f"status={device['status']} flags={anomaly_flags}")

    return jsonify({
        "device_id": device_id,
        "trust_score": device["trust_score"],
        "status": device["status"],
        "anomalies": anomaly_flags,
    })


@app.route("/status", methods=["GET"])
def get_status():
    """Returns current status of all devices — polled by the dashboard."""
    result = []
    for device_id, d in devices.items():
        result.append({
            "device_id": device_id,
            "trust_score": d["trust_score"],
            "status": d["status"],
            "last_seen": d["last_seen"],
            "last_temperature": d["history"][-1]["temperature"] if d["history"] else None,
        })
    return jsonify(result)


@app.route("/", methods=["GET"])
def home():
    return "ImmuneIoT backend running. POST sensor data to /data, GET status from /status."


if __name__ == "__main__":
    # host 0.0.0.0 so ESP32 on the same WiFi network can reach this machine's IP
    app.run(host="0.0.0.0", port=5000, debug=True)
