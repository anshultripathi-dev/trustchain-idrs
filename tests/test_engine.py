"""End-to-end behaviour of the closed loop (fast, in-memory, virtual clock)."""
import pytest

from trustchain.config import Settings
from trustchain.detection.train import ensure_model
from trustchain.engine import SMART_HOME_ID, Engine
from trustchain.ledger.contract import ACTIVE, QUARANTINED, RECOVERY_PENDING

FAN = "did:trustchain:fan:001"


@pytest.fixture(scope="module")
def model():
    return ensure_model(Settings().model_dir)


def engine(model, hour=14.0, seed=3):
    e = Engine(Settings(in_memory=True, virtual_clock=True), model=model, seed=seed, start_hour=hour)
    for _ in range(15):
        e.step()
    return e


def run(e, n):
    for _ in range(n):
        e.step()


def test_clean_traffic_raises_no_events_and_ledger_is_consistent(model):
    e = engine(model)
    run(e, 300)
    assert e.store.count() == 0
    assert all(d["status"] == ACTIVE and d["trust"] == 100 for d in e.contract.list_devices())
    assert e.network.audit()["consistent"]


def test_brute_force_escalates_then_quarantines_and_sounds_alarm(model):
    e = engine(model)
    e.launch_attack("BRUTE_FORCE", SMART_HOME_ID)
    run(e, 30)
    evs = e.store.list_events(10)[::-1]
    assert evs[0]["event_type"] == "BRUTE_FORCE" and evs[0]["severity"] == "HIGH"       # first sighting
    assert evs[-1]["severity"] == "CRITICAL" and evs[-1]["action"] == "QUARANTINE_DEVICE"  # attack memory escalates
    dev = e.contract.get_device(SMART_HOME_ID)
    assert dev["status"] == QUARANTINED and dev["trust"] < 100
    assert e.node.snapshot()["mode"] == "ALERT" and e.node.snapshot()["red_led"]
    assert e.network.audit()["consistent"]
    # every event on the ledger matches its local record
    assert all(e.contract.verifyAttackRecord(x["event_id"], e.store.recompute_hash(x["event_id"]))["match"] for x in evs)


def test_stealth_surge_is_invisible_to_static_rules_but_caught(model):
    e = engine(model, hour=2.0)
    a = e.launch_attack("STEALTH_SURGE", SMART_HOME_ID)
    run(e, 12)
    last = e.runtimes[SMART_HOME_ID].last
    assert last["sample"]["req_rate"] < 10 and not last["rules"]      # static rules blind
    assert e.store.count() >= 1                                       # ML + baseline catch it
    assert e.store.list_events(1)[0]["event_type"] in ("STEALTH_SURGE", "ML_BEHAVIOR_ANOMALY")


def test_replay_and_spoofing_do_not_quarantine_the_victim(model):
    e = engine(model)
    e.launch_attack("REPLAY", SMART_HOME_ID); e.launch_attack("SPOOFING", FAN)
    run(e, 20)
    types = {x["event_type"] for x in e.store.list_events(20)}
    assert {"REPLAY", "SPOOFING"} <= types
    assert e.contract.get_device(SMART_HOME_ID)["status"] == ACTIVE
    assert e.contract.get_device(FAN)["status"] == ACTIVE
    assert e.counters["dropped_blocked"] > 0                            # source blocklisted at gateway


def test_rogue_device_is_quarantined_and_cannot_be_restored(model):
    e = engine(model)
    e.launch_attack("ROGUE_DEVICE")
    run(e, 6)
    rogue = [d for d in e.contract.list_devices() if d.get("unregistered")]
    assert rogue and rogue[0]["status"] == QUARANTINED
    res = e.recovery_check(rogue[0]["device_id"])
    assert not res["passed"] and not res["checks"]["identity_registered"]["ok"]


def test_local_log_tampering_lowers_trust_and_is_detected(model):
    e = engine(model)
    e.launch_attack("SERVICE_PROBING", FAN)
    run(e, 5)
    e.stop_attacks()
    e.run_integrity()
    before = e.contract.get_device(FAN)
    assert before["status"] == ACTIVE
    e.tamper_local()
    rep = e.run_integrity()
    assert rep["status"] == "TAMPERING_DETECTED" and rep["mismatches"][0]["kind"] == "HASH_MISMATCH"
    after = e.contract.get_device(FAN)
    assert after["trust"] < before["trust"]                              # ledger integrity -> trust feedback
    assert any(x["event_type"] == "AUDIT_TAMPERING" for x in e.store.list_events(10))
    # repair from ledger restores the record's hashed fields
    ev_id = rep["mismatches"][0]["event_id"]
    assert e.repair_record(ev_id)["repaired"]
    assert e.integrity.scan_records() == []


def test_deleting_a_log_record_is_detected(model):
    e = engine(model)
    e.launch_attack("REQUEST_FLOOD", FAN)
    run(e, 4)
    e.stop_attacks()
    e.tamper_local(mode="delete")
    kinds = {m["kind"] for m in e.run_integrity()["mismatches"]}
    assert "MISSING_RECORD" in kinds


def test_tampered_validator_is_detected_and_network_keeps_running(model):
    e = engine(model)
    e.launch_attack("BRUTE_FORCE", SMART_HOME_ID)
    run(e, 6)
    e.stop_attacks()
    e.tamper_ledger("node-2")
    rep = e.run_integrity()
    assert rep["new_node_faults"] and rep["ledger"]["nodes"][1]["valid"] is False
    h = e.contract.height
    e.network.submit("SYSTEM_NOTE", {"x": 1})
    assert e.network.node("node-1").height() == h + 1
    e.network.heal("node-2")
    assert e.network.audit()["consistent"]


def test_recovery_is_administrator_gated_and_reversible(model):
    e = engine(model)
    e.launch_attack("REQUEST_FLOOD", FAN)
    run(e, 25)
    assert e.contract.get_device(FAN)["status"] == QUARANTINED
    assert not e.recovery_check(FAN)["passed"]                        # attack still running
    run(e, 40)                                                          # attack over, device behaves
    res = e.recovery_check(FAN)
    assert res["passed"] and e.contract.get_device(FAN)["status"] == RECOVERY_PENDING
    assert e.node.snapshot()["mode"] == "ALERT"                         # still alarmed until admin approves
    e.approve_recovery(FAN, "alice", "re-flashed firmware")
    d = e.contract.get_device(FAN)
    assert d["status"] == ACTIVE and d["trust"] == 60
    run(e, 3)
    assert e.node.snapshot()["mode"] == "SAFE"


def test_quarantine_blocks_commands_both_directions_and_lock_is_fail_secure(model):
    e = engine(model)
    e.manual_quarantine(FAN)
    r = e.send_command("did:trustchain:bulb:001", "off", from_device=FAN)       # outbound blocked
    assert not r["allowed"]
    r = e.send_command(FAN, "on")                                               # inbound blocked
    assert not r["allowed"]
    e.manual_quarantine(SMART_HOME_ID)
    r = e.send_command(SMART_HOME_ID, "unlock")
    assert not r["allowed"] and "FAIL-SECURE" in r["reason"]
    assert e.runtimes[SMART_HOME_ID].state["lock"] == "LOCKED"                  # state untouched


def test_low_trust_origin_cannot_unlock(model):
    e = engine(model)
    e.contract.updateTrustScore("did:trustchain:bulb:001", 55, "test")
    r = e.send_command(SMART_HOME_ID, "unlock", from_device="did:trustchain:bulb:001")
    assert not r["allowed"] and "trust" in r["reason"]


def test_state_survives_restart_by_replaying_the_chain(tmp_path, model):
    s = Settings(data_dir=str(tmp_path), virtual_clock=True)
    e1 = Engine(s, model=model, seed=1, start_hour=14)
    e1.launch_attack("BRUTE_FORCE", SMART_HOME_ID)
    run(e1, 25)
    status, trust = e1.contract.get_device(SMART_HOME_ID)["status"], e1.contract.get_device(SMART_HOME_ID)["trust"]
    e2 = Engine(Settings(data_dir=str(tmp_path), virtual_clock=True), model=model, seed=2, start_hour=14)
    d = e2.contract.get_device(SMART_HOME_ID)
    assert d["status"] == status and d["trust"] == trust
    assert e2.store.count() == e1.store.count() and e2.network.audit()["consistent"]
