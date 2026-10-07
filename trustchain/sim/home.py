"""The simulated smart home: rooms and devices.

Each device has a ledger-enrolled identity, a traffic profile (an archetype from `profiles.py`,
optionally tuned), a monetary value, a category and a quarantine fail-mode that says what
"safe" means for *that* device when it is isolated:

    fail-secure   keep the current state, block remote opening/unlocking (lock, garage door)
    fail-safe-off remote start is blocked, remote OFF/stop is still honoured (oven, water heater, ...)
    keep-running  never interrupt the service (fridge, router, smoke detector, ...)
    standard      remote commands are blocked while quarantined
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from .profiles import PROFILES, Profile

ROOMS: list[dict[str, str]] = [
    {"id": "entrance", "name": "Entrance", "icon": "🚪", "zone": "Indoor"},
    {"id": "living", "name": "Living room", "icon": "🛋️", "zone": "Indoor"},
    {"id": "kitchen", "name": "Kitchen", "icon": "🍳", "zone": "Indoor"},
    {"id": "hallway", "name": "Hallway", "icon": "🧭", "zone": "Indoor"},
    {"id": "bedroom", "name": "Master bedroom", "icon": "🛏️", "zone": "Indoor"},
    {"id": "bathroom", "name": "Bathroom", "icon": "🛁", "zone": "Indoor"},
    {"id": "office", "name": "Home office", "icon": "💻", "zone": "Indoor"},
    {"id": "utility", "name": "Utility room", "icon": "🧺", "zone": "Utility"},
    {"id": "garage", "name": "Garage", "icon": "🚗", "zone": "Utility"},
    {"id": "garden", "name": "Garden & pool", "icon": "🌿", "zone": "Outdoor"},
]

CATEGORIES: dict[str, dict[str, str]] = {
    "security": {"label": "Security", "icon": "🛡️"},
    "safety": {"label": "Safety", "icon": "🚨"},
    "climate": {"label": "Climate & water", "icon": "🌡️"},
    "appliance": {"label": "Appliances", "icon": "🏠"},
    "entertainment": {"label": "Entertainment", "icon": "🎬"},
    "comfort": {"label": "Comfort & lighting", "icon": "💡"},
    "energy": {"label": "Energy", "icon": "⚡"},
    "network": {"label": "Network & data", "icon": "📡"},
}

FAIL_MODES = {
    "fail-secure": "Keeps its current state; remote open/unlock is blocked, local access still works.",
    "fail-safe-off": "Remote start is blocked; a remote OFF / stop is still honoured so it can be made safe.",
    "keep-running": "Service is never interrupted; only remote control commands are blocked.",
    "standard": "Remote commands are blocked while quarantined.",
}


@dataclass(frozen=True)
class DeviceSpec:
    id: str
    name: str
    kind: str                 # traffic archetype (key in PROFILES)
    dtype: str                # device type: drives commands and policy
    room: str
    category: str
    value_usd: int
    icon: str
    model: str = ""
    critical: bool = False    # safety-critical (fire, flood, access, food, connectivity)
    fail_mode: str = "standard"
    tune: dict[str, Any] = field(default_factory=dict)

    def profile(self) -> Profile:
        return replace(PROFILES[self.kind], **self.tune) if self.tune else PROFILES[self.kind]


def _d(slug: str, n: int, name: str, kind: str, dtype: str, room: str, category: str, value: int, icon: str,
       model: str = "", critical: bool = False, fail: str = "standard", **tune: Any) -> DeviceSpec:
    return DeviceSpec(f"did:trustchain:{slug}:{n:03d}", name, kind, dtype, room, category, value, icon, model, critical, fail, tune)


# The five original devices keep their identifiers (hybrid mode, tests and docs refer to them).
CORE: list[DeviceSpec] = [
    DeviceSpec("did:trustchain:esp32:001", "ESP-1 Smart Door Lock", "smart_home_node", "smart_home_node", "entrance", "security", 220, "🔐",
               "ESP32 + keypad + servo lock · DHT11", True, "fail-secure"),
    DeviceSpec("did:trustchain:esp32:002", "ESP-2 Security Node", "security_node", "security_node", "hallway", "security", 60, "🛡️",
               "ESP32 + LCD, LEDs, buzzer", True, "keep-running"),
    DeviceSpec("did:trustchain:bulb:001", "Living-room Lamp", "bulb", "bulb", "living", "comfort", 35, "💡", "Dimmable smart bulb"),
    DeviceSpec("did:trustchain:fan:001", "Bedroom Fan", "fan", "fan", "bedroom", "climate", 180, "🌀", "3-speed smart fan"),
    DeviceSpec("did:trustchain:door:001", "Front-door Sensor", "door_sensor", "door_sensor", "entrance", "security", 40, "🚪", "Contact sensor", False, "keep-running"),
]

EXTRA: list[DeviceSpec] = [
    # Entrance & security
    _d("doorbell", 1, "Video Doorbell", "camera", "doorbell", "entrance", "security", 230, "🔔", "2K doorbell camera", False, "keep-running"),
    _d("camera", 1, "Front Camera", "camera", "camera", "entrance", "security", 320, "📹", "4K outdoor camera", False, "keep-running"),
    # Living room
    _d("tv", 1, 'OLED TV 65"', "media", "tv", "living", "entertainment", 2400, "📺", '65" OLED, 4K 120 Hz'),
    _d("soundbar", 1, "Soundbar + Subwoofer", "media", "soundbar", "living", "entertainment", 900, "🔊", "Dolby Atmos 5.1.2"),
    _d("vacuum", 1, "Robot Vacuum", "motor", "robot_vacuum", "living", "appliance", 800, "🤖", "LiDAR robot vacuum + mop", peak=11.0),
    _d("blinds", 1, "Motorised Blinds", "motor", "blinds", "living", "comfort", 1200, "🪟", "4-window motorised set", peak=7.5),
    _d("purifier", 1, "Air Purifier", "climate", "air_purifier", "living", "climate", 450, "🌬️", "HEPA + VOC sensor"),
    # Kitchen
    _d("fridge", 1, "Smart Refrigerator", "fridge", "fridge", "kitchen", "appliance", 3200, "🧊", "French-door, touchscreen", True, "keep-running"),
    _d("oven", 1, "Smart Oven", "oven", "oven", "kitchen", "appliance", 2100, "🔥", "Wall oven with remote preheat", True, "fail-safe-off"),
    _d("dishwasher", 1, "Dishwasher", "appliance", "dishwasher", "kitchen", "appliance", 1100, "🍽️", "Wi-Fi dishwasher", False, "fail-safe-off"),
    _d("coffee", 1, "Espresso Machine", "appliance", "coffee_machine", "kitchen", "appliance", 700, "☕", "Bean-to-cup, app scheduling", False, "fail-safe-off", peak=7.0, sharp=8.0),
    # Hallway
    _d("router", 1, "Mesh Wi-Fi Router", "network", "router", "hallway", "network", 450, "📡", "Wi-Fi 7 tri-band mesh", True, "keep-running"),
    _d("thermostat", 1, "Smart Thermostat", "climate", "thermostat", "hallway", "climate", 250, "🌡️", "Learning thermostat", False, "keep-running"),
    _d("smoke", 1, "Smoke & CO Detector", "safety_sensor", "smoke_detector", "hallway", "safety", 120, "🚨", "Photoelectric + CO", True, "keep-running"),
    # Master bedroom
    _d("bed", 1, "Smart Bed", "personal", "smart_bed", "bedroom", "comfort", 4500, "🛏️", "Sleep tracking, temperature zones", False, "standard", peak=23.0),
    _d("ac", 1, "Air Conditioner", "climate", "ac", "bedroom", "climate", 1600, "❄️", "Inverter split AC", False, "standard", peak=22.0, sharp=2.0),
    _d("speaker", 1, "Smart Speaker", "personal", "smart_speaker", "bedroom", "entertainment", 250, "🔈", "Voice assistant speaker", peak=20.0),
    # Bathroom
    _d("heater", 1, "Water Heater", "climate", "water_heater", "bathroom", "climate", 900, "♨️", "Smart storage water heater", True, "fail-safe-off", peak=7.0, sharp=3.0),
    _d("shower", 1, "Digital Shower", "personal", "shower", "bathroom", "comfort", 1500, "🚿", "Thermostatic digital shower", False, "fail-safe-off", peak=7.5, sharp=6.0),
    _d("mirror", 1, "Smart Mirror", "personal", "smart_mirror", "bathroom", "comfort", 600, "🪞", "Touch mirror with display", peak=7.5),
    _d("leak", 1, "Water-leak Sensor", "safety_sensor", "leak_sensor", "bathroom", "safety", 60, "💧", "Floor leak sensor", True, "keep-running"),
    # Home office
    _d("nas", 1, "Network Storage (NAS)", "network", "nas", "office", "network", 1000, "🗄️", "4-bay NAS, photo & backup vault", True, "keep-running", peak=2.0, sharp=1.0),
    _d("printer", 1, "Wireless Printer", "personal", "printer", "office", "appliance", 300, "🖨️", "Laser printer", False, "standard", peak=11.0, sharp=4.0),
    # Utility room
    _d("washer", 1, "Washing Machine", "appliance", "washer", "utility", "appliance", 1300, "🧺", "Front-load, 10 kg", False, "fail-safe-off", peak=10.0),
    _d("dryer", 1, "Dryer", "appliance", "dryer", "utility", "appliance", 1200, "👕", "Heat-pump dryer", False, "fail-safe-off", peak=11.0),
    _d("meter", 1, "Smart Energy Meter", "energy", "energy_meter", "utility", "energy", 350, "⚡", "Whole-home CT meter", False, "keep-running"),
    _d("battery", 1, "Home Battery", "energy", "home_battery", "utility", "energy", 9500, "🔋", "13.5 kWh home battery", True, "keep-running", peak=19.0),
    _d("solar", 1, "Solar Inverter", "energy", "solar_inverter", "utility", "energy", 3800, "☀️", "6 kW hybrid inverter", False, "keep-running", peak=13.0, sharp=3.0),
    # Garage
    _d("garage", 1, "Garage Door", "motor", "garage_door", "garage", "security", 600, "🚘", "Belt-drive opener", True, "fail-secure", peak=8.0, sharp=4.0),
    _d("ev", 1, "EV Charger", "energy", "ev_charger", "garage", "energy", 900, "🔌", "11 kW wall charger", False, "fail-safe-off", peak=1.0, sharp=3.0),
    # Garden & pool
    _d("irrigation", 1, "Irrigation Controller", "motor", "irrigation", "garden", "climate", 200, "🌱", "8-zone sprinkler controller", False, "fail-safe-off", peak=5.5, sharp=10.0),
    _d("pool", 1, "Pool Pump", "motor", "pool_pump", "garden", "appliance", 1100, "🏊", "Variable-speed pool pump", False, "fail-safe-off", peak=13.0, sharp=3.0),
    _d("camera", 2, "Backyard Camera", "camera", "camera", "garden", "security", 320, "📹", "4K outdoor camera", False, "keep-running"),
]

FULL: list[DeviceSpec] = CORE + EXTRA


def catalog(home: str = "full") -> list[DeviceSpec]:
    return list(CORE if home == "core" else FULL)


def room_of(spec: DeviceSpec) -> dict[str, str]:
    return next(r for r in ROOMS if r["id"] == spec.room)


def validate() -> list[str]:
    """Catalog consistency problems (empty list = OK). Used by tests."""
    problems = []
    ids = [d.id for d in FULL]
    if len(ids) != len(set(ids)):
        problems.append("duplicate device ids")
    rooms = {r["id"] for r in ROOMS}
    for d in FULL:
        if d.kind not in PROFILES:
            problems.append(f"{d.id}: unknown profile {d.kind}")
        if d.room not in rooms:
            problems.append(f"{d.id}: unknown room {d.room}")
        if d.category not in CATEGORIES:
            problems.append(f"{d.id}: unknown category {d.category}")
        if d.fail_mode not in FAIL_MODES:
            problems.append(f"{d.id}: unknown fail mode {d.fail_mode}")
        if d.tune:
            d.profile()  # raises on bad override fields
    return problems
