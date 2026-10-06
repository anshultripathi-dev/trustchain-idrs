#include <WiFi.h>
#include <WebServer.h>
#include <Wire.h>
#include <LiquidCrystal_I2C.h>

// =====================================================
// Wi-Fi
// =====================================================

const char* ssid = "YOUR_WIFI_SSID";
const char* password = "YOUR_WIFI_PASSWORD";

// =====================================================
// ESP32 #2 Security Hardware
// =====================================================

#define GREEN_LED 25
#define RED_LED   26
#define BUZZER    27

// =====================================================
// LCD
// =====================================================

#define LCD_SDA 21
#define LCD_SCL 22

LiquidCrystal_I2C lcd(0x27, 16, 2);

// =====================================================
// Web Server
// =====================================================

WebServer server(80);

// =====================================================
// Security State
// =====================================================

bool intrusionActive = false;
String currentAlert = "SAFE";

unsigned long bootTime = 0;
unsigned long totalRequests = 0;
unsigned long lastRequestTime = 0;

// =====================================================
// LCD Helper
// =====================================================

void lcdMessage(String line1, String line2) {

  lcd.clear();

  lcd.setCursor(0, 0);
  lcd.print(line1.substring(0, 16));

  lcd.setCursor(0, 1);
  lcd.print(line2.substring(0, 16));
}

// =====================================================
// SAFE STATE
// =====================================================

void setSafeState() {

  intrusionActive = false;
  currentAlert = "SAFE";

  digitalWrite(GREEN_LED, HIGH);
  digitalWrite(RED_LED, LOW);
  digitalWrite(BUZZER, LOW);

  lcdMessage(
    "SYSTEM STATUS",
    "SAFE"
  );

  Serial.println("SECURITY STATE: SAFE");
}

// =====================================================
// ALERT STATE
// =====================================================

void setAlertState(String alertType) {

  intrusionActive = true;
  currentAlert = alertType;

  digitalWrite(GREEN_LED, LOW);
  digitalWrite(RED_LED, HIGH);
  digitalWrite(BUZZER, HIGH);

  lcd.clear();

  lcd.setCursor(0, 0);
  lcd.print("!! INTRUSION !!");

  lcd.setCursor(0, 1);

  if (alertType.length() <= 16) {
    lcd.print(alertType);
  } else {
    lcd.print(alertType.substring(0, 16));
  }

  Serial.println("SECURITY ALERT: " + alertType);
}

// =====================================================
// Request Logger
// =====================================================

void recordRequest() {

  totalRequests++;
  lastRequestTime = millis();
}

// =====================================================
// ROOT
// =====================================================

void handleRoot() {

  recordRequest();

  String html = "";

  html += "<!DOCTYPE html>";
  html += "<html>";
  html += "<head>";
  html += "<title>ESP32 Security Controller</title>";
  html += "<meta name='viewport' content='width=device-width,initial-scale=1'>";
  html += "</head>";

  html += "<body>";
  html += "<h1>ESP32 Security Controller</h1>";

  html += "<h2>Status: ";
  html += currentAlert;
  html += "</h2>";

  html += "<p>Intrusion Active: ";
  html += intrusionActive ? "YES" : "NO";
  html += "</p>";

  html += "<p>Total Requests: ";
  html += String(totalRequests);
  html += "</p>";

  html += "<p>";
  html += "<a href='/safe'>SAFE</a>";
  html += "</p>";

  html += "<p>";
  html += "<a href='/alert?type=TEST'>TEST ALERT</a>";
  html += "</p>";

  html += "</body>";
  html += "</html>";

  server.send(200, "text/html", html);
}

// =====================================================
// SAFE ROUTE
// =====================================================

void handleSafe() {

  recordRequest();

  setSafeState();

  server.send(
    200,
    "application/json",
    "{\"status\":\"SAFE\",\"intrusion\":false}"
  );
}

// =====================================================
// ALERT ROUTE
// =====================================================

void handleAlert() {

  recordRequest();

  String type = server.arg("type");

  if (type == "") {
    type = "INTRUSION";
  }

  setAlertState(type);

  String json = "{";
  json += "\"status\":\"ALERT\",";
  json += "\"intrusion\":true,";
  json += "\"type\":\"" + type + "\"";
  json += "}";

  server.send(200, "application/json", json);
}

// =====================================================
// MANUAL RED ALERT
// =====================================================

void handleRed() {

  recordRequest();

  setAlertState("MANUAL");

  server.send(
    200,
    "application/json",
    "{\"status\":\"ALERT\",\"type\":\"MANUAL\"}"
  );
}

// =====================================================
// GREEN LED
// =====================================================

void handleGreen() {

  recordRequest();

  // Do not allow green LED to override a real intrusion
  if (intrusionActive) {

    server.send(
      403,
      "application/json",
      "{\"error\":\"Intrusion active. Cannot clear manually.\"}"
    );

    return;
  }

  digitalWrite(GREEN_LED, HIGH);

  server.send(
    200,
    "application/json",
    "{\"green_led\":true}"
  );
}

// =====================================================
// BUZZER ON
// =====================================================

void handleBuzzerOn() {

  recordRequest();

  digitalWrite(BUZZER, HIGH);

  server.send(
    200,
    "application/json",
    "{\"buzzer\":true}"
  );
}

// =====================================================
// BUZZER OFF
// =====================================================

void handleBuzzerOff() {

  recordRequest();

  // Don't silence an active intrusion
  if (intrusionActive) {

    server.send(
      403,
      "application/json",
      "{\"error\":\"Intrusion active. Buzzer cannot be disabled.\"}"
    );

    return;
  }

  digitalWrite(BUZZER, LOW);

  server.send(
    200,
    "application/json",
    "{\"buzzer\":false}"
  );
}

// =====================================================
// STATUS
// =====================================================

void handleStatus() {

  recordRequest();

  unsigned long uptime = millis() - bootTime;

  String json = "{";

  json += "\"device\":\"ESP32_SECURITY_CONTROLLER\",";
  json += "\"ip\":\"" + WiFi.localIP().toString() + "\",";
  json += "\"uptime_ms\":" + String(uptime) + ",";
  json += "\"status\":\"" + currentAlert + "\",";
  json += "\"intrusion_active\":";
  json += intrusionActive ? "true" : "false";
  json += ",";

  json += "\"green_led\":";
  json += digitalRead(GREEN_LED) ? "true" : "false";
  json += ",";

  json += "\"red_led\":";
  json += digitalRead(RED_LED) ? "true" : "false";
  json += ",";

  json += "\"buzzer\":";
  json += digitalRead(BUZZER) ? "true" : "false";
  json += ",";

  json += "\"lcd\":\"0x27\",";
  json += "\"total_requests\":" + String(totalRequests) + ",";
  json += "\"last_request_ms\":" + String(lastRequestTime) + ",";
  json += "\"wifi_rssi\":" + String(WiFi.RSSI());

  json += "}";

  server.send(
    200,
    "application/json",
    json
  );
}

// =====================================================
// 404
// =====================================================

void handleNotFound() {

  recordRequest();

  server.send(
    404,
    "application/json",
    "{\"error\":\"Not Found\"}"
  );
}

// =====================================================
// Wi-Fi Connection
// =====================================================

void connectWiFi() {

  Serial.println();
  Serial.println("Connecting to Wi-Fi...");

  WiFi.mode(WIFI_STA);

  WiFi.begin(
    ssid,
    password
  );

  int attempts = 0;

  while (
    WiFi.status() != WL_CONNECTED &&
    attempts < 30
  ) {

    delay(500);

    Serial.print(".");

    attempts++;
  }

  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {

    Serial.println("Wi-Fi connected!");
    Serial.print("ESP32 #2 IP: ");
    Serial.println(WiFi.localIP());

    Serial.print("Gateway: ");
    Serial.println(WiFi.gatewayIP());

    Serial.print("RSSI: ");
    Serial.println(WiFi.RSSI());

  } else {

    Serial.println("Wi-Fi connection failed.");
  }
}

// =====================================================
// Setup
// =====================================================

void setup() {

  Serial.begin(115200);

  delay(1000);

  Serial.println();
  Serial.println("==============================");
  Serial.println("ESP32 SECURITY CONTROLLER");
  Serial.println("==============================");

  // ---------------------------------------------------
  // GPIO
  // ---------------------------------------------------

  pinMode(GREEN_LED, OUTPUT);
  pinMode(RED_LED, OUTPUT);
  pinMode(BUZZER, OUTPUT);

  digitalWrite(GREEN_LED, LOW);
  digitalWrite(RED_LED, LOW);
  digitalWrite(BUZZER, LOW);

  // ---------------------------------------------------
  // I2C LCD
  // ---------------------------------------------------

  Wire.begin(
    LCD_SDA,
    LCD_SCL
  );

  lcd.init();
  lcd.backlight();

  lcdMessage(
    "SECURITY SYSTEM",
    "STARTING..."
  );

  delay(1500);

  // ---------------------------------------------------
  // SAFE INITIAL STATE
  // ---------------------------------------------------

  setSafeState();

  // ---------------------------------------------------
  // Wi-Fi
  // ---------------------------------------------------

  connectWiFi();

  // ---------------------------------------------------
  // Web Routes
  // ---------------------------------------------------

  server.on(
    "/",
    HTTP_GET,
    handleRoot
  );

  server.on(
    "/safe",
    HTTP_GET,
    handleSafe
  );

  server.on(
    "/alert",
    HTTP_GET,
    handleAlert
  );

  server.on(
    "/red",
    HTTP_GET,
    handleRed
  );

  server.on(
    "/green",
    HTTP_GET,
    handleGreen
  );

  server.on(
    "/buzzer/on",
    HTTP_GET,
    handleBuzzerOn
  );

  server.on(
    "/buzzer/off",
    HTTP_GET,
    handleBuzzerOff
  );

  server.on(
    "/status",
    HTTP_GET,
    handleStatus
  );

  server.onNotFound(
    handleNotFound
  );

  // ---------------------------------------------------
  // Start Server
  // ---------------------------------------------------

  server.begin();

  bootTime = millis();

  Serial.println("Web server started.");

  Serial.print("Open: http://");
  Serial.print(WiFi.localIP());
  Serial.println("/");

  Serial.println("==============================");
}

// =====================================================
// Loop
// =====================================================

void loop() {

  server.handleClient();

  // ---------------------------------------------------
  // Automatic Wi-Fi reconnect
  // ---------------------------------------------------

  static unsigned long lastWiFiCheck = 0;

  if (millis() - lastWiFiCheck > 10000) {

    lastWiFiCheck = millis();

    if (WiFi.status() != WL_CONNECTED) {

      Serial.println("Wi-Fi disconnected. Reconnecting...");

      WiFi.disconnect();
      WiFi.begin(
        ssid,
        password
      );
    }
  }
}
