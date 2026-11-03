/*
  ImmuneIoT v3 - ESP32 firmware (DHT11 + IR sensor only, no extra parts)
  Readings sent every 5 s:
    temperature, humidity   (DHT11, GPIO4)
    ir                      (IR obstacle sensor OUT, GPIO27: 1 = obstacle)
    ir_toggles              (how many times the IR output flipped since last send)
    rssi                    (WiFi signal strength, dBm)
    chip_temp               (ESP32 internal temperature sensor)
  Status feedback: onboard LED (GPIO2)
    solid = TRUSTED, slow blink = WARNING, fast blink = QUARANTINED
  Demo: type 'a' in Serial Monitor to toggle ATTACK MODE.

  WIRING
    DHT11 : VCC->3V3, GND->GND, DATA->GPIO4
    IR    : VCC->3V3, GND->GND, OUT->GPIO27
*/

#include <WiFi.h>
#include <HTTPClient.h>
#include <DHT.h>

// ---------- CONFIG - EDIT THESE ----------
const char* WIFI_SSID     = "papoi";
const char* WIFI_PASSWORD = "9876543211";
const char* SERVER_IP     = "192.168.137.30";
const int   SERVER_PORT   = 5000;
const char* DEVICE_ID     = "esp32_01";
// ------------------------------------------

#define DHTPIN  4
#define DHTTYPE DHT11
#define IR_PIN  27
#define LED_PIN 2

DHT dht(DHTPIN, DHTTYPE);

bool attackMode = false;
unsigned long lastSend = 0;
const unsigned long normalInterval = 5000;
const unsigned long attackInterval = 200;
const unsigned long wifiRetryInterval = 10000;
unsigned long lastWifiTry = 0;

int lastIr = HIGH;
int irToggles = 0;

String currentStatus = "TRUSTED";
unsigned long lastBlink = 0;
bool ledState = false;

void updateLed() {
  if (currentStatus == "TRUSTED") { digitalWrite(LED_PIN, HIGH); return; }
  unsigned long period = (currentStatus == "WARNING") ? 600 : 120;
  if (millis() - lastBlink >= period) {
    lastBlink = millis();
    ledState = !ledState;
    digitalWrite(LED_PIN, ledState);
  }
}

// Robust against whitespace: handles "status":"X" and "status": "X"
String parseStatus(const String& body) {
  int k = body.indexOf("\"status\"");
  if (k < 0) return "";
  int colon = body.indexOf(':', k);
  if (colon < 0) return "";
  int q1 = body.indexOf('"', colon + 1);
  if (q1 < 0) return "";
  int q2 = body.indexOf('"', q1 + 1);
  if (q2 < 0) return "";
  return body.substring(q1 + 1, q2);
}

void addField(String& s, const char* key, float v, int digits = 1) {
  s += "\""; s += key; s += "\":";
  s += isnan(v) ? String("null") : String(v, digits);
  s += ",";
}

void connectWiFi(unsigned long timeoutMs) {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.print("Connecting to WiFi");
  unsigned long start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < timeoutMs) {
    delay(500);
    Serial.print(".");
  }
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\nConnected! IP: " + WiFi.localIP().toString());
  } else {
    Serial.println("\nWiFi not connected yet, will keep retrying.");
  }
}

void setup() {
  Serial.begin(115200);
  dht.begin();
  pinMode(IR_PIN, INPUT);
  pinMode(LED_PIN, OUTPUT);
  lastIr = digitalRead(IR_PIN);

  WiFi.setAutoReconnect(true);
  connectWiFi(20000);
  Serial.println("Type 'a' + Enter to toggle ATTACK MODE.");
}

void loop() {
  while (Serial.available()) {
    char c = Serial.read();
    if (c == 'a' || c == 'A') {
      attackMode = !attackMode;
      Serial.println(attackMode ? ">>> ATTACK MODE ON <<<" : ">>> back to normal <<<");
    }
  }

  // poll IR fast so we can count how often it flips
  int ir = digitalRead(IR_PIN);
  if (ir != lastIr) { irToggles++; lastIr = ir; }

  updateLed();

  // non-blocking WiFi recovery
  if (WiFi.status() != WL_CONNECTED) {
    if (millis() - lastWifiTry >= wifiRetryInterval) {
      lastWifiTry = millis();
      Serial.println("WiFi lost, reconnecting...");
      WiFi.disconnect();
      WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    }
    delay(5);
    return;
  }

  unsigned long interval = attackMode ? attackInterval : normalInterval;
  if (millis() - lastSend >= interval) {
    lastSend = millis();
    sendReading();
  }
  delay(5);
}

void sendReading() {
  float temp = dht.readTemperature();
  float hum  = dht.readHumidity();
  float chip = temperatureRead();
  int   rssi = WiFi.RSSI();
  int   ir   = (digitalRead(IR_PIN) == LOW) ? 1 : 0;   // most IR modules: LOW = obstacle
  int   toggles = irToggles;
  irToggles = 0;

  if (attackMode) {                 // spoofed / compromised data
    temp    = 90.0 + random(0, 60);
    hum     = 100.0 + random(0, 50);
    toggles = random(100, 500);
  }

  String body = "{\"device_id\":\"" + String(DEVICE_ID) + "\",";
  addField(body, "temperature", temp);
  addField(body, "humidity", hum);
  addField(body, "chip_temp", chip);
  body += "\"rssi\":" + String(rssi) + ",";
  body += "\"ir_toggles\":" + String(toggles) + ",";
  body += "\"ir\":" + String(ir) + "}";

  HTTPClient http;
  http.setTimeout(2000);            // don't freeze the loop if the server is down
  http.begin("http://" + String(SERVER_IP) + ":" + String(SERVER_PORT) + "/data");
  http.addHeader("Content-Type", "application/json");
  int code = http.POST(body);
  Serial.println(body + " | HTTP " + String(code));
  if (code == 200) {
    String s = parseStatus(http.getString());
    if (s.length() > 0) currentStatus = s;   // keep old status if parsing fails
  }
  http.end();
}
