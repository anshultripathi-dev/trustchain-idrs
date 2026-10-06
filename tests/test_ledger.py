import json

import pytest

from trustchain.crypto import KeyPair, canonical, sha256_hex, verify
from trustchain.ledger.chain import LedgerError, LedgerNetwork, LedgerNode
from trustchain.ledger.contract import ContractError, SecurityContract, escalate


def make_net(n=3):
    nodes = [LedgerNode(f"node-{i+1}", KeyPair.generate()) for i in range(n)]
    net = LedgerNetwork(nodes)
    net.init_genesis()
    return net


def event(i=1, device="dev-1", sev="HIGH"):
    return {"event_id": f"EVT-{i}", "device_id": device, "event_type": "BRUTE_FORCE", "severity": sev,
            "risk_score": 0.9, "event_hash": sha256_hex(f"e{i}"), "fingerprint": "fp1", "ts": 1000.0 + i,
            "source": "10.0.0.9"}


def test_sign_verify_roundtrip():
    k = KeyPair.generate()
    sig = k.sign(b"hello")
    assert verify(k.public_hex, b"hello", sig)
    assert not verify(k.public_hex, b"hellO", sig)
    assert not verify(KeyPair.generate().public_hex, b"hello", sig)


def test_chain_grows_with_quorum_signatures():
    net = make_net()
    c = SecurityContract(net)
    c.registerDevice("dev-1", "Dev", "sensor", KeyPair.generate().public_hex)
    b = c.recordAttack(event())
    assert b.index == 2 and len(b.signatures) >= 2
    assert all(n.height() == 3 for n in net.nodes)
    assert net.audit()["consistent"]


def test_payload_tamper_detected_and_pinpointed():
    net = make_net()
    c = SecurityContract(net)
    c.registerDevice("dev-1", "Dev", "sensor", KeyPair.generate().public_hex)
    c.recordAttack(event())
    node = net.node("node-2")
    d = node.get(2).to_dict()
    d["payload"]["severity"] = "LOW"
    node.overwrite_raw(2, d)
    audit = net.audit()
    assert not audit["consistent"]
    bad = next(r for r in audit["nodes"] if r["node"] == "node-2")
    assert not bad["valid"] and bad["first_bad_index"] == 2
    # the other two nodes are still fine
    assert all(r["valid"] for r in audit["nodes"] if r["node"] != "node-2")


def test_attacker_who_rehashes_chain_still_fails_signature_check():
    net = make_net()
    c = SecurityContract(net)
    c.registerDevice("dev-1", "Dev", "sensor", KeyPair.generate().public_hex)
    c.recordAttack(event())
    c.recordAttack(event(2))
    node = net.node("node-3")
    blocks = node.blocks()
    # rewrite block 2 and recompute every later hash/link (no validator keys available)
    d = blocks[2].to_dict()
    d["payload"]["severity"] = "LOW"
    prev = None
    for i in (2, 3):
        b = blocks[i]
        if i == 2:
            b.payload = d["payload"]
        else:
            b.prev_hash = prev.hash
        b.hash = b.compute_hash()
        node.overwrite_raw(i, b.to_dict())
        prev = b
    r = node.verify_chain()
    assert not r["valid"]
    assert "signature" in r["errors"][0]["error"]


def test_tampered_node_is_excluded_and_healed():
    net = make_net()
    c = SecurityContract(net)
    c.registerDevice("dev-1", "Dev", "sensor", KeyPair.generate().public_hex)
    c.recordAttack(event())
    node = net.node("node-1")
    d = node.get(2).to_dict()
    d["payload"]["risk_score"] = 0.01
    node.overwrite_raw(2, d)
    net.audit()
    assert "node-1" in net.flagged
    c.recordAttack(event(2))  # chain keeps working on remaining quorum
    assert net.node("node-2").height() == 4 and node.height() == 3
    net.heal("node-1")
    assert net.audit()["consistent"]


def test_no_quorum_when_majority_offline():
    net = make_net()
    net.node("node-1").online = False
    net.node("node-2").online = False
    with pytest.raises(LedgerError):
        net.submit("X", {})


def test_offline_node_catches_up():
    net = make_net()
    c = SecurityContract(net)
    net.node("node-3").online = False
    c.registerDevice("dev-1", "Dev", "sensor", KeyPair.generate().public_hex)
    net.node("node-3").online = True
    c.recordAttack(event())
    assert net.node("node-3").height() == net.node("node-1").height()
    assert net.audit()["consistent"]


def test_contract_state_is_replayable_from_chain():
    net = make_net()
    c = SecurityContract(net)
    pub = KeyPair.generate().public_hex
    c.registerDevice("dev-1", "Dev", "sensor", pub)
    c.recordAttack(event())
    r = c.updateTrustScore("dev-1", 15, "test")
    assert r["quarantine_required"]
    c.quarantineDevice("dev-1", "trust below 20")
    fresh = SecurityContract(net)
    fresh.rebuild()
    assert fresh.devices["dev-1"]["status"] == "QUARANTINED"
    assert fresh.devices["dev-1"]["trust"] == 15
    assert fresh.verifyDevice("dev-1", pub) and not fresh.verifyDevice("dev-1", "00")


def test_restore_requires_recovery_verification():
    net = make_net()
    c = SecurityContract(net)
    c.registerDevice("dev-1", "Dev", "sensor", KeyPair.generate().public_hex)
    c.quarantineDevice("dev-1", "x")
    with pytest.raises(ContractError):
        c.restoreDevice("dev-1", "admin")
    c.recordRecoveryVerified("dev-1", {"ok": True})
    c.restoreDevice("dev-1", "admin", "cleaned")
    d = c.get_device("dev-1")
    assert d["status"] == "ACTIVE" and d["trust"] == 60


def test_attack_memory_escalates_severity():
    net = make_net()
    c = SecurityContract(net)
    c.registerDevice("dev-1", "Dev", "sensor", KeyPair.generate().public_hex)
    assert c.assess_recurrence("fp1", "10.0.0.9", "BRUTE_FORCE", 1100)["escalate_levels"] == 0
    c.recordAttack(event(1))
    assert c.assess_recurrence("fp1", "10.0.0.9", "BRUTE_FORCE", 1100)["escalate_levels"] == 1
    c.recordAttack(event(2)); c.recordAttack(event(3))
    assert c.assess_recurrence("fp1", "10.0.0.9", "BRUTE_FORCE", 1100)["escalate_levels"] == 2
    assert escalate("HIGH", 2) == "CRITICAL" and escalate("LOW", 1) == "MEDIUM"


def test_verify_attack_record():
    net = make_net()
    c = SecurityContract(net)
    c.registerDevice("dev-1", "Dev", "sensor", KeyPair.generate().public_hex)
    e = event()
    c.recordAttack(e)
    assert c.verifyAttackRecord("EVT-1", e["event_hash"])["match"]
    assert c.verifyAttackRecord("EVT-1", "deadbeef")["result"] == "MISMATCH"
    assert c.verifyAttackRecord("EVT-9", "x")["result"] == "NOT_ON_CHAIN"
