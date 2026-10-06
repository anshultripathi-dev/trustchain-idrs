# Firmware

Arduino sketches for the two ESP32 boards. They are the original two-board IDS firmware and work with
TrustChain-IDRS **unchanged**.

| Sketch | Board | Role |
|---|---|---|
| [`esp1/esp1.ino`](esp1/esp1.ino) | ESP32 #1 | Smart-home node: DHT11, keypad PIN lock, servo, LEDs, web dashboard, `GET /security/status` |
| [`esp2/esp2.ino`](esp2/esp2.ino) | ESP32 #2 | Security node: red/green LEDs, buzzer, LCD, `GET /alert`, `/safe`, `/status` |

Before flashing, set your Wi-Fi in each sketch. **The committed files contain placeholders — never commit real credentials.**

```cpp
const char* ssid = "YOUR_WIFI_SSID";
const char* password = "YOUR_WIFI_PASSWORD";
```

Pin maps, libraries and flashing steps are in [`../docs/HARDWARE.md`](../docs/HARDWARE.md). A git-ignored
`firmware/.local/` folder is a safe place for a private copy with credentials.

The sketches do not sign their messages; in hybrid mode the gateway attests for ESP32 #1. On-device ECDSA signing
is on the roadmap.
