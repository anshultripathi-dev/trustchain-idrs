import pytest
from fastapi.testclient import TestClient

from trustchain import api
from trustchain.config import Settings

H = {"X-Admin-Token": "admin"}


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    import os
    os.environ["TRUSTCHAIN_DATA"] = str(tmp_path_factory.mktemp("data"))
    with TestClient(api.app) as c:
        yield c


def test_overview_and_session(client):
    assert client.get("/api/session").json()["mode"] == "sim"
    ov = client.get("/api/overview").json()
    assert len(ov["devices"]) == 5 and ov["ledger"]["consistent"]


def test_admin_endpoints_require_token(client):
    assert client.post("/api/attacks", json={"type": "BRUTE_FORCE"}).status_code == 401
    assert client.post("/api/tamper/local", json={}, headers={"X-Admin-Token": "nope"}).status_code == 401
    assert client.post("/api/commands", json={"to": "did:trustchain:bulb:001", "command": "off"}).status_code == 401


def test_attack_flow_through_api(client):
    r = client.post("/api/attacks", json={"type": "ROGUE_DEVICE"}, headers=H)
    assert r.status_code == 200
    import time; time.sleep(3)
    ev = client.get("/api/events").json()["events"]
    assert any(e["event_type"] == "ROGUE_DEVICE" for e in ev)
    e0 = next(e for e in ev if e["event_type"] == "ROGUE_DEVICE")
    detail = client.get(f"/api/events/{e0['event_id']}").json()
    assert detail["verification"]["result"] == "MATCH"
    assert client.get("/api/ledger/blocks").json()["blocks"]


def test_unknown_attack_is_400(client):
    assert client.post("/api/attacks", json={"type": "NOPE"}, headers=H).status_code == 400
