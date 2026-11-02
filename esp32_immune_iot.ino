/*
  ImmuneIoT - ESP32 Firmware
  Reads a DHT11 sensor and POSTs readings to the Flask backend over HTTP.
  Includes a built-in "attack mode" that you trigger for the demo by
  sending the character 'a' over Serial — it fakes compromised behaviour
  (fast messages + extreme values) WITHOUT needing a second device or
  real hacking.

  Before uploading:
  1. Install "DHT sensor library" by Adafruit (Library Manager)
  2. Set WIFI_SSID, WIFI_PASSWORD, SERVER_IP below
  3. Change DEVICE_ID per board (esp32_01, esp32_02, esp32_03...)
*/

#include <WiFi.h>
#include <HTTPClient.h>
#include <DHT.h>

// ---------- CONFIG — EDIT THESE ----------
const char* WIFI_SSID     = "YOUR_WIFI_NAME";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";
const char* SERVER_IP     = "192.168.1.XXX";  // your laptop's local IP (ipconfig / ifconfig)
const int   SERVER_PORT   = 5000;
const char* DEVICE_ID     = "esp32_01";       // change per board!
// ------------------------------------------

#define DHTPIN 4          // GPIO pin the DHT11 data pin is connected to
#define DHTTYPE DHT11
DHT dht(DHTPIN, DHTTYPE);

bool attackMode = false;
unsigned long lastSend = 0;
unsigned long normalInterval = 5000;   // 5 sec between messages normally
unsigned long attackInterval = 200;    // 0.2 sec between messages when "attacked"

void setup() {
  Serial.begin(115200);
  dht.begin();

  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nConnected! IP: " + WiFi.localIP().toString());
  Serial.println("Type 'a' + Enter in Serial Monitor to toggle ATTACK MODE for the demo.");
}

void loop() {
  // --- check for demo trigger over Serial ---
  if (Serial.available()) {
    char c = Serial.read();
    if (c == 'a') {
      attackMode = !attackMode;
      Serial.println(attackMode ? ">>> ATTACK MODE ON <<<" : ">>> back to normal <<<");
    }
  }

  unsigned long interval = attackMode ? attackInterval : normalInterval;

  if (millis() - lastSend >= interval) {
    lastSend = millis();
    sendReading();
  }
}

void sendReading() {
  float temperature = dht_readTemperature_safe();

  if (attackMode) {
    // fake an extreme/impossible value to simulate compromised sensor data
    temperature = 90.0 + random(0, 60);  // 90-150 range, clearly abnormal
  }

  if (isnan(temperature)) {
    Serial.println("Failed to read sensor, skipping this cycle.");
    return;
  }

  if (WiFi.status() == WL_CONNECTED) {
    HTTPClient http;
    String url = "http://" + String(SERVER_IP) + ":" + String(SERVER_PORT) + "/data";
    http.begin(url);
    http.addHeader("Content-Type", "application/json");

    String jsonBody = "{\"device_id\":\"" + String(DEVICE_ID) +
                       "\",\"temperature\":" + String(temperature) + "}";

    int httpResponseCode = http.POST(jsonBody);

    Serial.print("Sent temp=");
    Serial.print(temperature);
    Serial.print(" | HTTP ");
    Serial.println(httpResponseCode);

    http.end();
  } else {
    Serial.println("WiFi disconnected!");
  }
}

float dht_readTemperature_safe() {
  return dht.readTemperature();
}
