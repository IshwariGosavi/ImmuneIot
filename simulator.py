"""
ImmuneIoT - Multi-device Simulator (backup demo without hardware)

Fakes 4 devices sending readings to the Flask backend.
While it runs, type a device number (1-4) and press ENTER to toggle
ATTACK MODE on that device. Type the same number again to stop the attack.
You can attack several at once. Press Ctrl+C to stop.

Run: python simulator.py   (app.py must already be running)
"""

import random
import threading
import time

import requests

SERVER = "http://localhost:5000/data"
NUM_DEVICES = 4

attacked = set()


def listen_for_toggle():
    while True:
        text = input().strip()
        if text.isdigit() and 1 <= int(text) <= NUM_DEVICES:
            n = int(text)
            if n in attacked:
                attacked.discard(n)
                print(f">>> sim_0{n} back to normal <<<")
            else:
                attacked.add(n)
                print(f">>> ATTACK MODE ON for sim_0{n} <<<")
        else:
            print(f"Type a number from 1 to {NUM_DEVICES}")


def send(device_id, temperature):
    try:
        r = requests.post(SERVER, json={"device_id": device_id, "temperature": temperature}, timeout=2)
        data = r.json()
        print(f"{device_id}: temp={temperature:.1f} -> {data['status']} ({data['trust_score']})")
    except Exception as e:
        print("Could not reach backend:", e)


def device_loop(n):
    device_id = f"sim_0{n}"
    while True:
        if n in attacked:
            temperature = random.uniform(90, 150)
            interval = 0.3
        else:
            temperature = random.uniform(26, 31)
            interval = 5
        send(device_id, temperature)
        time.sleep(interval)


if __name__ == "__main__":
    print(f"Simulating {NUM_DEVICES} devices. Type 1-{NUM_DEVICES} + ENTER to attack/stop a device.")
    threading.Thread(target=listen_for_toggle, daemon=True).start()
    for i in range(2, NUM_DEVICES + 1):
        threading.Thread(target=device_loop, args=(i,), daemon=True).start()
    device_loop(1)