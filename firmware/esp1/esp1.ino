#include <WiFi.h>
#include <WebServer.h>
#include <ESP32Servo.h>
#include <Keypad.h>
#include "DHT.h"

// =====================================================
// WIFI
// =====================================================

const char* ssid = "YOUR_WIFI_SSID";
const char* password = "YOUR_WIFI_PASSWORD";

// =====================================================
// LEDS
// =====================================================
const int LED1_PIN = 25;
const int LED2_PIN = 26;

const int PWM_FREQ = 5000;
const int PWM_RESOLUTION = 8;

bool led1State = false;
bool led2State = false;

int led1Brightness = 50;
int led2Brightness = 50;

// =====================================================
// DHT11
// =====================================================

#define DHT_PIN 4
#define DHT_TYPE DHT11

DHT dht(DHT_PIN, DHT_TYPE);

float temperature = 0.0;
float humidity = 0.0;

unsigned long lastDHTRead = 0;
const unsigned long DHT_INTERVAL = 2000;

// =====================================================
// SG90 SMART LOCK
// =====================================================

const int SERVO_PIN = 18;

const int LOCK_POSITION = 0;
const int UNLOCK_POSITION = 90;

Servo lockServo;

bool lockState = true;

// =====================================================
// KEYPAD
// =====================================================

const byte ROWS = 4;
const byte COLS = 4;

char keys[ROWS][COLS] = {

  {'1', '2', '3', 'A'},
  {'4', '5', '6', 'B'},
  {'7', '8', '9', 'C'},
  {'*', '0', '#', 'D'}

};

// Row pins
byte rowPins[ROWS] = {
  13,
  14,
  27,
  32
};

// Column pins
byte colPins[COLS] = {
  19,
  21,
  22,
  23
};

Keypad keypad = Keypad(
  makeKeymap(keys),
  rowPins,
  colPins,
  ROWS,
  COLS
);

// =====================================================
// PIN
// =====================================================

const String CORRECT_PIN = "1111";

String enteredPIN = "";

String lockStatus = "LOCKED";

// =====================================================
// SECURITY / IDS TELEMETRY
// =====================================================
// These counters let the Python IDS measure activity on ESP32 #1.
// The counters are intentionally simple and reset only when the ESP32 restarts.
unsigned long totalRequests = 0;
unsigned long failedPINAttempts = 0;
unsigned long successfulPINAttempts = 0;
unsigned long lastRequestMillis = 0;
String lastSecurityEvent = "SYSTEM_START";

void recordRequest(const String& eventName) {
  totalRequests++;
  lastRequestMillis = millis();
  lastSecurityEvent = eventName;
}

void recordSecurityEvent(const String& eventName) {
  lastSecurityEvent = eventName;
}

// =====================================================
// WEB SERVER
// =====================================================

WebServer server(80);


// =====================================================
// BRIGHTNESS TO PWM
// =====================================================

int brightnessToPWM(int brightness) {

  brightness = constrain(
    brightness,
    0,
    100
  );

  return map(
    brightness,
    0,
    100,
    0,
    255
  );
}


// =====================================================
// UPDATE LEDS
// =====================================================

void updateLEDs() {

  if (led1State) {

    ledcWrite(
      LED1_PIN,
      brightnessToPWM(
        led1Brightness
      )
    );

  } else {

    ledcWrite(
      LED1_PIN,
      0
    );

  }


  if (led2State) {

    ledcWrite(
      LED2_PIN,
      brightnessToPWM(
        led2Brightness
      )
    );

  } else {

    ledcWrite(
      LED2_PIN,
      0
    );

  }

}


// =====================================================
// READ DHT11
// =====================================================

void readDHT() {

  if (
    millis() - lastDHTRead >=
    DHT_INTERVAL
  ) {

    lastDHTRead = millis();

    float newHumidity =
      dht.readHumidity();

    float newTemperature =
      dht.readTemperature();


    if (
      !isnan(newHumidity) &&
      !isnan(newTemperature)
    ) {

      humidity =
        newHumidity;

      temperature =
        newTemperature;


      Serial.print(
        "Temperature: "
      );

      Serial.print(
        temperature
      );

      Serial.print(
        " C | Humidity: "
      );

      Serial.print(
        humidity
      );

      Serial.println(
        " %"
      );

    }

  }

}


// =====================================================
// CHECK PIN
// =====================================================

void checkPIN() {

  Serial.print(
    "Entered PIN: "
  );

  Serial.println(
    enteredPIN
  );


  if (
    enteredPIN == CORRECT_PIN
  ) {

    // Correct PIN

    lockServo.write(
      UNLOCK_POSITION
    );

    lockState = false;

    lockStatus = "UNLOCKED";


    successfulPINAttempts++;
    recordSecurityEvent("PIN_SUCCESS");

    Serial.println(
      "Correct PIN - UNLOCKED"
    );

  }

  else {

    // Wrong PIN

    lockServo.write(
      LOCK_POSITION
    );

    lockState = true;

    lockStatus = "WRONG PIN";


    failedPINAttempts++;
    recordSecurityEvent("PIN_FAILURE");

    Serial.println(
      "Wrong PIN"
    );

  }


  enteredPIN = "";

}


// =====================================================
// READ KEYPAD
// =====================================================

void readKeypad() {

  char key =
    keypad.getKey();


  if (!key) {
    return;
  }


  Serial.print(
    "Key pressed: "
  );

  Serial.println(
    key
  );


  // ===================================================
  // STAR = CLEAR / LOCK
  // ===================================================

  if (key == '*') {

    enteredPIN = "";

    lockServo.write(
      LOCK_POSITION
    );

    lockState = true;

    lockStatus = "LOCKED";


    Serial.println(
      "PIN cleared - LOCKED"
    );

    return;

  }


  // ===================================================
  // HASH = MANUAL CHECK
  // ===================================================

  if (key == '#') {

    if (
      enteredPIN.length() > 0
    ) {

      checkPIN();

    }

    return;

  }


  // ===================================================
  // NUMERIC KEYS
  // ===================================================

  if (
    key >= '0' &&
    key <= '9'
  ) {

    if (
      enteredPIN.length() < 6
    ) {

      enteredPIN += key;

      lockStatus =
        "ENTER PIN";


      // Automatically check
      // after 4 digits

      if (
        enteredPIN.length() == 4
      ) {

        checkPIN();

      }

    }

  }

}


// =====================================================
// MAIN WEBPAGE
// =====================================================

String webpage() {

  String html = R"rawliteral(

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width, initial-scale=1"
>

<title>ESP32 Smart Home</title>


<style>

/* =====================================================
   GENERAL
   ===================================================== */

* {
  box-sizing: border-box;
}


body {

  font-family: Arial, sans-serif;

  background: #f2f2f2;

  margin: 0;

  padding: 20px;

  text-align: center;

}


.container {

  max-width: 850px;

  margin: auto;

}


h1 {

  color: #222;

  margin-bottom: 30px;

}


/* =====================================================
   CARDS
   ===================================================== */

.card {

  background: white;

  padding: 25px;

  margin: 20px 0;

  border-radius: 18px;

  box-shadow:
    0 4px 15px rgba(0,0,0,0.12);

}


.card h2 {

  margin-top: 0;

}


/* =====================================================
   LED
   ===================================================== */

.led-grid {

  display: grid;

  grid-template-columns:
    repeat(2, 1fr);

  gap: 20px;

}


@media (max-width: 600px) {

  .led-grid {

    grid-template-columns: 1fr;

  }

}


.led-status {

  font-size: 22px;

  font-weight: bold;

  margin: 15px;

}


.led-on {

  color: #28a745;

}


.led-off {

  color: #dc3545;

}


button {

  border: none;

  padding: 13px 25px;

  margin: 5px;

  font-size: 17px;

  border-radius: 9px;

  cursor: pointer;

}


.on-button {

  background: #28a745;

  color: white;

}


.off-button {

  background: #dc3545;

  color: white;

}


.clear-button {

  background: #333;

  color: white;

}


input[type="range"] {

  width: 90%;

}


.brightness-value {

  font-size: 20px;

  font-weight: bold;

}


/* =====================================================
   DHT GAUGES
   ===================================================== */

.gauge-container {

  display: flex;

  justify-content: center;

  align-items: center;

  gap: 50px;

  flex-wrap: wrap;

}


.gauge-wrapper {

  text-align: center;

}


.gauge {

  width: 180px;

  height: 180px;

  border-radius: 50%;

  background:
    conic-gradient(
      #2196f3 0deg,
      #ddd 0deg
    );

  display: flex;

  justify-content: center;

  align-items: center;

  position: relative;

}


.gauge::before {

  content: "";

  width: 135px;

  height: 135px;

  background: white;

  border-radius: 50%;

  position: absolute;

}


.gauge-content {

  position: relative;

  z-index: 2;

}


.gauge-value {

  font-size: 27px;

  font-weight: bold;

}


.gauge-label {

  font-size: 16px;

  color: #555;

  margin-top: 5px;

}


/* =====================================================
   SMART LOCK
   ===================================================== */

.lock-status {

  font-size: 32px;

  font-weight: bold;

  margin: 25px 0;

}


.locked {

  color: #dc3545;

}


.unlocked {

  color: #28a745;

}


.entering {

  color: #333;

}


.pin-display {

  font-size: 32px;

  letter-spacing: 10px;

  min-height: 45px;

  margin: 20px;

}


.lock-info {

  font-size: 18px;

  color: #555;

}


.lock-button {

  background: #dc3545;

  color: white;

}


</style>

</head>


<body>


<div class="container">


<h1>ESP32 Smart Home Dashboard</h1>


<!-- =================================================
     DHT11
     ================================================= -->

<div class="card">

<h2>DHT11 Environment Monitor</h2>


<div class="gauge-container">


<!-- TEMPERATURE -->

<div class="gauge-wrapper">

<div
class="gauge"
id="temperatureGauge"
>

<div class="gauge-content">

<div
class="gauge-value"
id="temperatureValue"
>
-- C
</div>

<div class="gauge-label">
Temperature
</div>

</div>

</div>

</div>


<!-- HUMIDITY -->

<div class="gauge-wrapper">

<div
class="gauge"
id="humidityGauge"
>

<div class="gauge-content">

<div
class="gauge-value"
id="humidityValue"
>
-- %
</div>

<div class="gauge-label">
Humidity
</div>

</div>

</div>

</div>


</div>


<p>
Temperature range: 0 - 50 C
</p>

<p>
Humidity range: 0 - 100 %
</p>


</div>


<!-- =================================================
     LEDS
     ================================================= -->

<div class="card">

<h2>LED Control</h2>


<div class="led-grid">


<!-- LED 1 -->

<div>

<h3>LED 1</h3>


<div
id="led1Status"
class="led-status led-off"
>
OFF
</div>


<button
id="led1Button"
class="off-button"
onclick="toggleLED(1)"
>
OFF
</button>


<br><br>


<label>
Brightness
</label>


<br><br>


<input
type="range"
min="0"
max="100"
value="50"
id="led1Slider"
oninput="setBrightness(1, this.value)"
>


<p class="brightness-value">

<span id="led1Brightness">
50
</span>%

</p>

</div>


<!-- LED 2 -->

<div>

<h3>LED 2</h3>


<div
id="led2Status"
class="led-status led-off"
>
OFF
</div>


<button
id="led2Button"
class="off-button"
onclick="toggleLED(2)"
>
OFF
</button>


<br><br>


<label>
Brightness
</label>


<br><br>


<input
type="range"
min="0"
max="100"
value="50"
id="led2Slider"
oninput="setBrightness(2, this.value)"
>


<p class="brightness-value">

<span id="led2Brightness">
50
</span>%

</p>

</div>


</div>


</div>


<!-- =================================================
     SMART LOCK
     ================================================= -->

<div class="card">

<h2>Smart Door Lock</h2>


<div
id="lockStatus"
class="lock-status locked"
>
LOCKED
</div>


<div
id="pinDisplay"
class="pin-display"
>
----
</div>


<p
id="lockMessage"
class="lock-info"
>
Enter PIN using the physical keypad
</p>


<p class="lock-info">

PIN is entered through the connected
4x4 keypad.

</p>


<button
class="lock-button"
onclick="clearPIN()"
>
CLEAR / LOCK
</button>


</div>


</div>


<script>


// =====================================================
// LED TOGGLE
// =====================================================

function toggleLED(led) {

  fetch(
    "/toggle?led=" + led
  )

  .then(
    response => response.text()
  )

  .then(
    data => {

      updateLEDStatus(
        led,
        data
      );

    }
  );

}


// =====================================================
// LED STATUS
// =====================================================

function updateLEDStatus(
  led,
  state
) {

  let status =
    document.getElementById(
      "led" + led + "Status"
    );


  let button =
    document.getElementById(
      "led" + led + "Button"
    );


  if (state == "ON") {

    status.innerText =
      "ON";

    status.className =
      "led-status led-on";

    button.innerText =
      "ON";

    button.className =
      "on-button";

  }

  else {

    status.innerText =
      "OFF";

    status.className =
      "led-status led-off";

    button.innerText =
      "OFF";

    button.className =
      "off-button";

  }

}


// =====================================================
// BRIGHTNESS
// =====================================================

function setBrightness(
  led,
  value
) {

  document.getElementById(
    "led" + led + "Brightness"
  ).innerText =
    value;


  fetch(
    "/brightness?led=" +
    led +
    "&value=" +
    value
  );

}


// =====================================================
// SENSOR DATA
// =====================================================

function updateSensorData() {

  fetch("/sensor")

  .then(
    response => response.json()
  )

  .then(
    data => {

      // -----------------------------------------------
      // TEMPERATURE
      // -----------------------------------------------

      let temp =
        parseFloat(
          data.temperature
        );


      if (!isNaN(temp)) {

        document.getElementById(
          "temperatureValue"
        ).innerText =
          temp.toFixed(1) +
          " C";


        let tempPercent =
          Math.min(
            Math.max(temp, 0),
            50
          ) / 50;


        let tempDegrees =
          tempPercent * 360;


        document.getElementById(
          "temperatureGauge"
        ).style.background =
          "conic-gradient(" +
          "#ff5722 " +
          tempDegrees +
          "deg, " +
          "#ddd " +
          tempDegrees +
          "deg)";

      }


      // -----------------------------------------------
      // HUMIDITY
      // -----------------------------------------------

      let hum =
        parseFloat(
          data.humidity
        );


      if (!isNaN(hum)) {

        document.getElementById(
          "humidityValue"
        ).innerText =
          hum.toFixed(1) +
          " %";


        let humDegrees =
          Math.min(
            Math.max(hum, 0),
            100
          ) * 3.6;


        document.getElementById(
          "humidityGauge"
        ).style.background =
          "conic-gradient(" +
          "#2196f3 " +
          humDegrees +
          "deg, " +
          "#ddd " +
          humDegrees +
          "deg)";

      }

    }
  )

  .catch(
    error =>
      console.log(
        "Sensor error:",
        error
      )
  );

}


// =====================================================
// LOCK STATUS
// =====================================================

function updateLockStatus() {

  fetch("/lockstatus")

  .then(
    response => response.json()
  )

  .then(
    data => {

      let status =
        document.getElementById(
          "lockStatus"
        );


      let pin =
        document.getElementById(
          "pinDisplay"
        );


      let message =
        document.getElementById(
          "lockMessage"
        );


      // -----------------------------------------------
      // STATUS
      // -----------------------------------------------

      status.innerText =
        data.status;


      if (
        data.status == "UNLOCKED"
      ) {

        status.className =
          "lock-status unlocked";

        message.innerText =
          "Correct PIN. Door is unlocked.";

      }

      else if (
        data.status == "WRONG PIN"
      ) {

        status.className =
          "lock-status locked";

        message.innerText =
          "Incorrect PIN. Try again.";

      }

      else if (
        data.status == "ENTER PIN"
      ) {

        status.className =
          "lock-status entering";

        message.innerText =
          "Enter PIN using the physical keypad.";

      }

      else {

        status.className =
          "lock-status locked";

        message.innerText =
          "Enter PIN using the physical keypad.";

      }


      // -----------------------------------------------
      // PIN DISPLAY
      // -----------------------------------------------

      let length =
        parseInt(
          data.pinLength
        );


      if (
        length == 0
      ) {

        pin.innerText =
          "----";

      }

      else {

        let stars = "";

        for (
          let i = 0;
          i < length;
          i++
        ) {

          stars += "*";

        }

        pin.innerText =
          stars;

      }

    }
  )

  .catch(
    error =>
      console.log(
        "Lock error:",
        error
      )
  );

}


// =====================================================
// CLEAR / LOCK
// =====================================================

function clearPIN() {

  fetch("/clear")

  .then(
    response => response.text()
  )

  .then(
    () => updateLockStatus()
  );

}


// =====================================================
// AUTO UPDATE
// =====================================================

setInterval(
  updateSensorData,
  2000
);


setInterval(
  updateLockStatus,
  300
);


// Initial updates

updateSensorData();

updateLockStatus();


</script>


</body>

</html>

)rawliteral";


  return html;

}


// =====================================================
// ROOT
// =====================================================

void handleRoot() {
  recordRequest("ROOT");

  server.send(
    200,
    "text/html; charset=UTF-8",
    webpage()
  );

}


// =====================================================
// LED TOGGLE
// =====================================================

void handleToggle() {
  recordRequest("TOGGLE");

  if (!server.hasArg("led")) {

    server.send(
      400,
      "text/plain",
      "Invalid LED"
    );

    return;

  }


  int led =
    server.arg("led").toInt();


  if (led == 1) {

    led1State =
      !led1State;

    updateLEDs();


    server.send(
      200,
      "text/plain",
      led1State ?
      "ON" :
      "OFF"
    );

  }

  else if (led == 2) {

    led2State =
      !led2State;

    updateLEDs();


    server.send(
      200,
      "text/plain",
      led2State ?
      "ON" :
      "OFF"
    );

  }

  else {

    server.send(
      400,
      "text/plain",
      "Invalid LED"
    );

  }

}


// =====================================================
// LED BRIGHTNESS
// =====================================================

void handleBrightness() {
  recordRequest("BRIGHTNESS");

  if (
    !server.hasArg("led") ||
    !server.hasArg("value")
  ) {

    server.send(
      400,
      "text/plain",
      "Invalid request"
    );

    return;

  }


  int led =
    server.arg("led").toInt();


  int value =
    server.arg("value").toInt();


  value =
    constrain(
      value,
      0,
      100
    );


  if (led == 1) {

    led1Brightness =
      value;

  }

  else if (led == 2) {

    led2Brightness =
      value;

  }

  else {

    server.send(
      400,
      "text/plain",
      "Invalid LED"
    );

    return;

  }


  updateLEDs();


  server.send(
    200,
    "text/plain",
    "OK"
  );

}


// =====================================================
// DHT SENSOR API
// =====================================================

void handleSensor() {
  recordRequest("SENSOR");

  String json = "{";


  json += "\"temperature\":";

  json += String(
    temperature,
    1
  );


  json += ",";


  json += "\"humidity\":";

  json += String(
    humidity,
    1
  );


  json += "}";


  server.send(
    200,
    "application/json",
    json
  );

}


// =====================================================
// LOCK STATUS API
// =====================================================

void handleLockStatus() {
  recordRequest("LOCK_STATUS");

  String json = "{";


  json += "\"status\":\"";

  json += lockStatus;

  json += "\",";


  json += "\"pinLength\":";

  json += String(
    enteredPIN.length()
  );


  json += "}";


  server.send(
    200,
    "application/json",
    json
  );

}


// =====================================================
// CLEAR / LOCK
// =====================================================

void handleClear() {
  recordRequest("CLEAR_LOCK");

  enteredPIN = "";

  lockStatus =
    "LOCKED";


  lockServo.write(
    LOCK_POSITION
  );


  lockState = true;


  Serial.println(
    "Smart Lock: LOCKED"
  );


  server.send(
    200,
    "text/plain",
    "LOCKED"
  );

}


// =====================================================
// SECURITY TELEMETRY API
// =====================================================
// Python IDS polls this endpoint. It does NOT modify the smart-home state.
// Example: http://<ESP32-IP>/security/status

void handleSecurityStatus() {
  String json = "{";

  json += "\"device\":\"ESP32_SMART_HOME\",";
  json += "\"ip\":\"" + WiFi.localIP().toString() + "\",";
  json += "\"uptime_ms\":" + String(millis()) + ",";
  json += "\"temperature\":" + String(temperature, 1) + ",";
  json += "\"humidity\":" + String(humidity, 1) + ",";
  json += "\"led1\":" + String(led1State ? 1 : 0) + ",";
  json += "\"led2\":" + String(led2State ? 1 : 0) + ",";
  json += "\"led1_brightness\":" + String(led1Brightness) + ",";
  json += "\"led2_brightness\":" + String(led2Brightness) + ",";
  json += "\"lock_state\":\"" + lockStatus + "\",";
  json += "\"pin_length\":" + String(enteredPIN.length()) + ",";
  json += "\"failed_pin_attempts\":" + String(failedPINAttempts) + ",";
  json += "\"successful_pin_attempts\":" + String(successfulPINAttempts) + ",";
  json += "\"total_requests\":" + String(totalRequests) + ",";
  json += "\"last_request_ms\":" + String(lastRequestMillis) + ",";
  json += "\"last_event\":\"" + lastSecurityEvent + "\",";
  json += "\"wifi_rssi\":" + String(WiFi.RSSI());
  json += "}";

  server.send(200, "application/json", json);
}

// Optional controlled lab event endpoint. It records an event for the IDS
// demonstration but does not perform any attack itself.
void handleSecurityEvent() {
  String type = server.arg("type");
  if (type.length() == 0) {
    type = "TEST_EVENT";
  }

  recordSecurityEvent(type);

  String json = "{\"recorded\":true,\"event\":\"" + type + "\"}";
  server.send(200, "application/json", json);
}

// =====================================================
// SETUP
// =====================================================

void setup() {

  Serial.begin(115200);


  // ===================================================
  // LED PWM
  // ===================================================

  ledcAttach(
    LED1_PIN,
    PWM_FREQ,
    PWM_RESOLUTION
  );


  ledcAttach(
    LED2_PIN,
    PWM_FREQ,
    PWM_RESOLUTION
  );


  ledcWrite(
    LED1_PIN,
    0
  );


  ledcWrite(
    LED2_PIN,
    0
  );


  // ===================================================
  // DHT11
  // ===================================================

  dht.begin();


  // ===================================================
  // SERVO
  // ===================================================

  lockServo.setPeriodHertz(50);


  lockServo.attach(
    SERVO_PIN,
    500,
    2400
  );


  lockServo.write(
    LOCK_POSITION
  );


  lockState = true;

  lockStatus =
    "LOCKED";


  // ===================================================
  // WIFI
  // ===================================================

  WiFi.begin(
    ssid,
    password
  );


  Serial.print(
    "Connecting to Wi-Fi"
  );


  while (
    WiFi.status() != WL_CONNECTED
  ) {

    delay(500);

    Serial.print(".");

  }


  Serial.println();


  Serial.println(
    "Wi-Fi connected!"
  );


  Serial.print(
    "ESP32 IP address: "
  );


  Serial.println(
    WiFi.localIP()
  );


  // ===================================================
  // WEB SERVER ROUTES
  // ===================================================

  server.on(
    "/",
    handleRoot
  );


  server.on(
    "/toggle",
    handleToggle
  );


  server.on(
    "/brightness",
    handleBrightness
  );


  server.on(
    "/sensor",
    handleSensor
  );


  server.on(
    "/lockstatus",
    handleLockStatus
  );


  server.on(
    "/clear",
    handleClear
  );

  // Security/IDS telemetry endpoints
  server.on(
    "/security/status",
    HTTP_GET,
    handleSecurityStatus
  );

  server.on(
    "/security/event",
    HTTP_GET,
    handleSecurityEvent
  );


  server.begin();


  Serial.println(
    "Web server started!"
  );


  Serial.println(
    "Smart Home System Ready"
  );

  Serial.print("Security telemetry: http://");
  Serial.print(WiFi.localIP());
  Serial.println("/security/status");


  Serial.println(
    "PIN: 1111"
  );

}


// =====================================================
// LOOP
// =====================================================

void loop() {

  server.handleClient();

  readDHT();

  readKeypad();

}
