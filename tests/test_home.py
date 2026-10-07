"""The full smart home: ~38 devices in 10 rooms, with per-device safety policies."""
import pytest

from trustchain.config import Settings
from trustchain.detection.train import ensure_model
from trustchain.engine import Engine
from trustchain.ledger.contract import ACTIVE, QUARANTINED
from trustchain.sim import home

OVEN = "did:trustchain:oven:001"
FRIDGE = "did:trustchain:fridge:001"
GARAGE = "did:trustchain:garage:001"
HEATER = "did:trustchain:heater:001"
FAN = "did:trustchain:fan:001"
ROUTER = "did:trustchain:router:001"
LOCK = "did:trustchain:esp32:001"


@pytest.fixture(scope="module")
def model():
    return ensure_model(Settings().model_dir)


def full_home(model, seed=11, hour=14.0):
    e = Engine(Settings(in_memory=True, virtual_clock=True, home="full"), model=model, seed=seed, start_hour=hour)
    for _ in range(15):
        e.step()
    return e


def run(e, n):
    for _ in range(n):
        e.step()


def test_catalog_is_consistent():
    assert home.validate() == []
    assert len(home.FULL) >= 35 and len(home.ROOMS) >= 9
    assert sum(d.value_usd for d in home.FULL) > 30_000          # an expensive, fully equipped home
    assert {d.id for d in home.CORE} <= {d.id for d in home.FULL}
    assert home.CORE[0].id == "did:trustchain:esp32:001"          # original identifiers are preserved


def test_every_room_has_devices_and_every_category_is_used():
    assert {d.room for d in home.FULL} == {r["id"] for r in home.ROOMS}
    assert {d.category for d in home.FULL} == set(home.CATEGORIES)


def test_full_home_boots_on_the_ledger_and_stays_quiet(model):
    e = full_home(model)
    assert len(e.runtimes) == len(home.FULL)
    assert all(not d.get("unregistered") for d in e.contract.list_devices())
    run(e, 120)
    assert e.network.audit()["consistent"]
    assert not [d for d in e.contract.list_devices() if d["status"] != ACTIVE]    # no false quarantines
    assert e.store.count() <= 3                                                    # at most a stray low-severity alert


def test_overview_groups_devices_into_rooms_with_value(model):
    e = full_home(model)
    ov = e.overview()
    assert sum(r["count"] for r in ov["rooms"]) == len(home.FULL)
    assert ov["home"]["value_usd"] == sum(d.value_usd for d in home.FULL)
    kitchen = next(r for r in ov["rooms"] if r["id"] == "kitchen")
    assert kitchen["count"] == 4 and kitchen["value_usd"] > 7000
    d = next(x for x in ov["devices"] if x["id"] == OVEN)
    assert d["room"] == "kitchen" and d["critical"] and d["fail_mode"] == "fail-safe-off" and "preheat" in d["commands"]


def test_attack_on_oven_quarantines_it_but_remote_off_still_works(model):
    e = full_home(model)
    e.launch_attack("REQUEST_FLOOD", OVEN)
    run(e, 30)
    assert e.contract.get_device(OVEN)["status"] == QUARANTINED
    blocked = e.send_command(OVEN, "preheat")
    assert not blocked["allowed"] and "FAIL-SAFE" in blocked["reason"]
    off = e.send_command(OVEN, "off")                               # hazard-reducing: always honoured
    assert off["allowed"] and off["state"]["power"] == "OFF"


def test_quarantined_garage_door_may_close_but_not_open(model):
    e = full_home(model)
    e.manual_quarantine(GARAGE)
    assert not e.send_command(GARAGE, "open")["allowed"]
    closed = e.send_command(GARAGE, "close")
    assert closed["allowed"] and closed["state"]["position"] == "CLOSED"


def test_quarantined_fridge_keeps_running(model):
    e = full_home(model)
    e.manual_quarantine(FRIDGE)
    r = e.send_command(FRIDGE, "boost_cool")
    assert not r["allowed"] and "KEEP-RUNNING" in r["reason"]


def test_fridge_sensor_tampering_is_caught_without_any_static_rule(model):
    e = full_home(model)
    e.launch_attack("SENSOR_ANOMALY", FRIDGE)       # e.g. spoofed compartment temperature (food-spoilage attack)
    run(e, 12)
    types = {x["event_type"] for x in e.store.list_events(20) if x["device_id"] == FRIDGE}
    assert "SENSOR_ANOMALY" in types


def test_weak_unexplained_evidence_never_escalates_to_quarantine(model):
    e = full_home(model)
    meta = {"source": "device", "port": 0, "protocol": "HTTP"}
    for _ in range(6):                               # repeated borderline ML anomalies on a healthy device
        e.clock.advance(20)
        e._raise_event(ROUTER, "ML_BEHAVIOR_ANOMALY", 0.9, meta, {"req_rate": 1, "failed_auth": 0}, {}, e.clock.now(), weak=True)
    sev = {x["severity"] for x in e.store.list_events(20) if x["device_id"] == ROUTER}
    assert sev <= {"LOW", "MEDIUM"}
    assert e.contract.get_device(ROUTER)["status"] == ACTIVE


def test_real_attacks_are_not_weak_and_still_quarantine(model):
    e = full_home(model)
    e.launch_attack("BRUTE_FORCE", LOCK)
    run(e, 30)
    assert e.contract.get_device(LOCK)["status"] == QUARANTINED


def test_model_trained_on_a_different_profile_set_is_retrained(model, tmp_path, monkeypatch):
    from trustchain.detection import train
    path = tmp_path / "intrusion_model.joblib"
    good = dict(model.metrics)
    try:
        model.metrics = {**good, "profiles_sig": "stale-signature"}
        model.save(str(path))
    finally:
        model.metrics = good
    calls = []
    monkeypatch.setattr(train, "train_and_evaluate", lambda: calls.append(1) or model)
    monkeypatch.setattr(train.ModelBundle, "save", lambda self, p: None)
    assert train.ensure_model(str(tmp_path)) is model and calls == [1]       # stale signature -> retrained

    fresh = tmp_path / "ok"
    fresh.mkdir()
    model.save(str(fresh / "intrusion_model.joblib"))                          # matching signature -> reused as-is
    monkeypatch.undo()
    assert train.ensure_model(str(fresh)).metrics.get("profiles_sig") == good["profiles_sig"]
