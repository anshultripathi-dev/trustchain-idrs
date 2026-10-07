"""FastAPI service: REST + WebSocket for the TrustChain-IDRS dashboard."""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import threading
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import ROOT, Settings
from .detection.baseline import Baseline
from .detection.train import ensure_model
from .engine import SMART_HOME_ID, Engine
from .sim.home import CATEGORIES, FAIL_MODES, ROOMS
from .ledger.chain import LedgerError
from .ledger.contract import ContractError
from .response import COMMANDS
from .sim.profiles import ATTACKS, PROFILES
from .store import event_hash

WEB_DIR = os.path.join(ROOT, "web")


class SafeJSON(JSONResponse):
    def render(self, content: Any) -> bytes:
        return json.dumps(content, default=lambda o: o.item() if hasattr(o, "item") else str(o),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")


class Holder:
    engine: Engine
    settings: Settings
    jobs: dict[str, dict[str, Any]]
    evaluation: dict[str, Any] | None = None


H = Holder()


def _load_evaluation(settings: Settings) -> dict[str, Any] | None:
    path = os.path.join(settings.data_dir, "evaluation.json")
    if os.path.exists(path):
        try:
            with open(path) as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None
    return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    H.settings = Settings()
    H.jobs = {}
    H.engine = Engine(H.settings)
    H.evaluation = _load_evaluation(H.settings)
    H.engine.start()
    print(f"\n  TrustChain-IDRS  mode={H.settings.mode}  http://{H.settings.host}:{H.settings.port}")
    print(f"  admin token: {'(default \"admin\" - set TRUSTCHAIN_ADMIN_TOKEN)' if H.settings.admin_token == 'admin' else '(from TRUSTCHAIN_ADMIN_TOKEN)'}\n")
    yield
    H.engine.stop()


app = FastAPI(title="TrustChain-IDRS", version="1.0", lifespan=lifespan, default_response_class=SafeJSON)


def E() -> Engine:
    return H.engine


def admin(x_admin_token: str | None = Header(default=None)) -> str:
    if x_admin_token != H.settings.admin_token:
        raise HTTPException(401, "admin token required")
    return "admin"


def demo(_: str = Depends(admin)) -> None:
    if not H.settings.demo_mode:
        raise HTTPException(403, "demo/simulation endpoints are disabled")


def _guard(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except (ValueError, KeyError) as exc:
        raise HTTPException(400, str(exc))
    except (ContractError, LedgerError) as exc:
        raise HTTPException(409, str(exc))


# ------------------------------------------------------------------ session / overview
@app.get("/api/session")
def session():
    return {"mode": H.settings.mode, "demo_mode": H.settings.demo_mode, "version": "1.0",
            "hardware": {"esp32_smart_home": bool(H.settings.esp32_smart_home_ip), "esp32_security": bool(H.settings.esp32_security_ip)}}


@app.post("/api/session/check")
def check_admin(_: str = Depends(admin)):
    return {"ok": True}


@app.get("/api/overview")
def overview():
    return E().overview()


@app.get("/api/feed")
def feed(since: int = 0, limit: int = 60):
    with E().lock:
        items = [f for f in E().feed if f["seq"] > since][:limit]
    return {"items": items, "seq": E().seq}


# ------------------------------------------------------------------ home
@app.get("/api/home")
def home():
    """The smart-home catalogue: rooms, categories, fail modes and every device with its value and policy."""
    e = E()
    with e.lock:
        devs = [{"id": rt.id, "name": rt.name, "dtype": rt.kind, "room": rt.spec.room, "category": rt.spec.category,
                 "value_usd": rt.spec.value_usd, "icon": rt.spec.icon, "model": rt.spec.model, "critical": rt.spec.critical,
                 "fail_mode": rt.spec.fail_mode, "commands": COMMANDS.get(rt.kind, [])} for rt in e.runtimes.values() if rt.spec]
        return {"mode": e.s.home, "rooms": ROOMS, "categories": CATEGORIES, "fail_modes": FAIL_MODES, "devices": devs,
                "totals": {"devices": len(devs), "value_usd": sum(d["value_usd"] for d in devs), "critical": sum(1 for d in devs if d["critical"])}}


# ------------------------------------------------------------------ devices
@app.get("/api/devices")
def devices():
    with E().lock:
        return {"devices": [E().device_view(rt, 60) for rt in E().runtimes.values()], "unknown": E().unknown_devices()}


@app.get("/api/devices/{device_id}")
def device_detail(device_id: str):
    e = E()
    with e.lock:
        rt = e.runtimes.get(device_id)
        if rt is None:
            d = e.contract.get_device(device_id)
            if d is None:
                raise HTTPException(404, "unknown device")
            return {"device": {"id": device_id, "name": d["name"], "kind": "unknown", "status": d["status"], "trust": d["trust"],
                               "unregistered": True, "quarantine": d.get("quarantine")},
                    "events": e.store.list_events(30, device_id=device_id), "trust_history": e.contract.trust_history.get(device_id, [])}
        v = e.device_view(rt, 240)
        return {"device": v, "events": e.store.list_events(30, device_id=device_id),
                "trust_history": e.contract.trust_history.get(device_id, [])[-80:],
                "baseline": {"req_rate": e.baseline.curve(device_id, "req_rate"), "primary": e.baseline.curve(device_id, "primary")},
                "commands": COMMANDS.get(rt.kind, [])}


@app.post("/api/devices/{device_id}/quarantine")
def quarantine(device_id: str, _: str = Depends(admin)):
    return _guard(E().manual_quarantine, device_id)


@app.post("/api/devices/{device_id}/recovery-check")
def recovery_check(device_id: str, _: str = Depends(admin)):
    return _guard(E().recovery_check, device_id)


@app.post("/api/devices/{device_id}/approve")
def approve(device_id: str, body: dict = Body(default={}), _: str = Depends(admin)):
    return _guard(E().approve_recovery, device_id, body.get("admin") or "admin", body.get("notes", ""))


@app.post("/api/commands")
def command(body: dict = Body(...), x_admin_token: str | None = Header(default=None)):
    frm = body.get("from_device") or None
    if frm is None and x_admin_token != H.settings.admin_token:
        raise HTTPException(401, "admin token required for dashboard-originated commands")
    return _guard(E().send_command, body.get("to"), body.get("command"), frm)


# ------------------------------------------------------------------ events / ledger
@app.get("/api/events")
def events(limit: int = 100, device_id: str | None = None, severity: str | None = None):
    with E().lock:
        rows = E().store.list_events(min(limit, 500), device_id, severity)
        for r in rows:
            r["verified"] = E().contract.verifyAttackRecord(r["event_id"], event_hash(r))["result"]
            r["device_name"] = E()._name(r["device_id"])
        return {"events": rows, "total": E().store.count()}


@app.get("/api/events/{event_id}")
def event_detail(event_id: str):
    e = E()
    with e.lock:
        local = e.store.get_event(event_id)
        chain = e.contract.events.get(event_id)
        if local is None and chain is None:
            raise HTTPException(404, "unknown event")
        recomputed = event_hash(local) if local else None
        verdict = e.contract.verifyAttackRecord(event_id, recomputed or "")
        if local is None:
            verdict["result"] = "LOCAL_RECORD_MISSING"
        block = None
        if chain:
            b = e.network.primary().get(chain["block"])
            block = b.to_dict() if b else None
        return {"local": local, "chain": chain, "block": block, "verification": verdict,
                "device_name": e._name((local or chain)["device_id"])}


@app.get("/api/ledger/blocks")
def blocks(limit: int = 30, before: int | None = None, node: str | None = None):
    e = E()
    n = e.network.node(node) if node else e.network.primary()
    h = n.height()
    end = h if before is None else min(before, h)
    start = max(0, end - limit)
    bl = [b.to_dict() for b in n.blocks(start, end - start)]
    bl.reverse()
    return {"node": n.node_id, "height": h, "blocks": bl, "start": start}


@app.get("/api/ledger/blocks/{index}")
def block_detail(index: int):
    e = E()
    per_node = {}
    for n in e.network.nodes:
        b = n.get(index)
        per_node[n.node_id] = b.to_dict() if b else None
    ref = next((b for b in per_node.values() if b), None)
    if ref is None:
        raise HTTPException(404, "no such block")
    agree = len({b["hash"] for b in per_node.values() if b}) == 1
    return {"block": ref, "per_node": {k: (v["hash"] if v else None) for k, v in per_node.items()}, "nodes_agree": agree,
            "recomputed_ok": {k: (bool(v) and _recompute(v) == v["hash"]) for k, v in per_node.items()}}


def _recompute(d: dict[str, Any]) -> str:
    from .ledger.chain import Block
    return Block.from_dict(d).compute_hash()


@app.get("/api/ledger/audit")
def audit():
    return E().network.audit()


@app.get("/api/ledger/state")
def ledger_state():
    e = E()
    with e.lock:
        return {"stats": e.contract.stats(), "registry": e.contract.list_devices(),
                "integrity_alerts": e.contract.integrity_alerts[-20:], "validators": e.network.nodes[0].validators() if e.network.nodes[0].height() else {}}


@app.post("/api/ledger/heal/{node}")
def heal(node: str, _: str = Depends(admin)):
    e = E()
    with e.lock:
        r = _guard(e.network.heal, node)
        e.integrity.forget_node_alerts(node)
        e.network.audit()
        e._post_feed("INTEGRITY", f"Validator {node} repaired from healthy majority", r)
        return r


@app.post("/api/ledger/node/{node}/online")
def node_online(node: str, body: dict = Body(...), _: str = Depends(demo)):
    e = E()
    with e.lock:
        n = _guard(e.network.node, node)
        n.online = bool(body.get("online", True))
        e._post_feed("SYSTEM", f"[simulation] validator {node} {'back online' if n.online else 'taken offline'}", {})
        return {"node": node, "online": n.online}


@app.get("/api/memory")
def memory():
    e = E()
    with e.lock:
        fps = sorted(e.contract.fingerprints.values(), key=lambda f: -f["last_ts"])
        srcs = sorted(e.contract.sources.values(), key=lambda s: -s["count"])
        return {"fingerprints": fps[:60], "sources": srcs[:40], "policy": {"window_s": e.contract.policy["recurrence_window_s"],
                "escalate_1": e.contract.policy["repeat_escalate_1"], "escalate_2": e.contract.policy["repeat_escalate_2"]}}


# ------------------------------------------------------------------ integrity / tamper
@app.post("/api/integrity/run")
def integrity_run(_: str = Depends(admin)):
    return E().run_integrity()


@app.get("/api/integrity")
def integrity_status():
    return E().integrity.last_report


@app.post("/api/integrity/repair/{event_id}")
def repair(event_id: str, _: str = Depends(admin)):
    return _guard(E().repair_record, event_id)


@app.post("/api/tamper/local")
def tamper_local(body: dict = Body(default={}), _: str = Depends(demo)):
    return _guard(E().tamper_local, body.get("event_id"), body.get("mode", "edit"))


@app.post("/api/tamper/ledger")
def tamper_ledger(body: dict = Body(default={}), _: str = Depends(demo)):
    return _guard(E().tamper_ledger, body.get("node", "node-2"), body.get("index"))


# ------------------------------------------------------------------ attacks
@app.get("/api/attacks")
def attacks():
    e = E()
    with e.lock:
        return {"catalog": [{"type": k, **v} for k, v in ATTACKS.items()], "active": [e._attack_view(a) for a in e.attacks],
                "log": list(e.attack_log), "devices": [{"id": rt.id, "name": rt.name, "kind": rt.kind, "room": rt.spec.room if rt.spec else None,
                                                                    "icon": rt.spec.icon if rt.spec else "", "real": rt.legacy is not None}
                                                                   for rt in e.runtimes.values()],
                "rooms": [{"id": r["id"], "name": r["name"], "icon": r["icon"]} for r in ROOMS]}


@app.post("/api/attacks")
def launch(body: dict = Body(...), _: str = Depends(demo)):
    return _guard(E().launch_attack, body.get("type"), body.get("device_id"), body.get("duration"))


@app.post("/api/attacks/stop")
def stop_attacks(_: str = Depends(demo)):
    return {"stopped": E().stop_attacks()}


# ------------------------------------------------------------------ ML
@app.get("/api/ml")
def ml():
    e = E()
    cur = {}
    with e.lock:
        for rt in e.runtimes.values():
            if rt.last:
                cur[rt.id] = {"name": rt.name, "ml": rt.last["ml"], "baseline": rt.last["fi"], "risk": rt.last["risk"]}
    return {"metrics": e.model.metrics, "live": cur, "evaluation": H.evaluation, "job": H.jobs.get("evaluation"), "retrain": H.jobs.get("retrain")}


@app.get("/api/ml/baseline")
def ml_baseline(device_id: str = SMART_HOME_ID, metric: str = "req_rate"):
    e = E()
    if device_id not in e.runtimes:
        raise HTTPException(404, "unknown device")
    rt = e.runtimes[device_id]
    return {"device_id": device_id, "metric": metric, "curve": e.baseline.curve(device_id, metric if metric in ("req_rate", "primary") else "req_rate"),
            "now_hour": e.sim_minute / 60.0, "recent": [{"hour": h["hour"], "value": h["req" if metric == "req_rate" else "primary"]} for h in list(rt.history)[-120:]]}


def _job(name: str, fn):
    if H.jobs.get(name, {}).get("running"):
        raise HTTPException(409, f"{name} already running")
    H.jobs[name] = {"running": True, "started": time.time(), "progress": []}

    def run():
        try:
            fn(H.jobs[name])
        except Exception as exc:
            H.jobs[name]["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            H.jobs[name]["running"] = False
            H.jobs[name]["finished"] = time.time()

    threading.Thread(target=run, daemon=True).start()
    return H.jobs[name]


@app.post("/api/ml/retrain")
def retrain(_: str = Depends(admin)):
    def go(job):
        model = ensure_model(H.settings.model_dir, retrain=True)
        with E().lock:
            E().model = model
            E()._post_feed("SYSTEM", "ML models retrained and hot-swapped", {"seconds": model.metrics.get("seconds")})
    return _job("retrain", go)


@app.post("/api/evaluation/run")
def run_evaluation(body: dict = Body(default={}), _: str = Depends(admin)):
    from .evaluation import evaluate
    trials = max(1, min(int(body.get("trials", 3)), 10))

    def go(job):
        res = evaluate(E().model, trials=trials, progress=lambda s: job["progress"].append(s))
        H.evaluation = res
        os.makedirs(H.settings.data_dir, exist_ok=True)
        with open(os.path.join(H.settings.data_dir, "evaluation.json"), "w") as fh:
            json.dump(res, fh, indent=2)
    return _job("evaluation", go)


# ------------------------------------------------------------------ hardware / sim
@app.get("/api/hardware")
def hardware():
    e = E()
    with e.lock:
        legacy = e.runtimes[SMART_HOME_ID].legacy
        return {"mode": H.settings.mode, "response_node": e.node.snapshot(),
                "smart_home": {"configured": legacy is not None, "connected": bool(legacy and legacy.connected), "ip": H.settings.esp32_smart_home_ip or None,
                               "raw": legacy.last_raw if legacy else None},
                "history": getattr(e.node, "history", [])[-15:]}


@app.post("/api/hardware/test")
def hardware_test(body: dict = Body(...), _: str = Depends(admin)):
    e = E()
    with e.lock:
        if body.get("action") == "alert":
            ok = e.node.alert("TEST_ALERT", "TEST ALERT")
        else:
            ok = e.node.safe()
        e._manual_until = e.clock.now() + 15   # keep the test visible, then the reconciler restores the true state
        e._phys_key = None
        return {"ok": ok, "state": e.node.snapshot()}


@app.post("/api/sim/clock")
def sim_clock(body: dict = Body(...), _: str = Depends(demo)):
    e = E()
    if "hour" in body:
        e.set_sim_hour(float(body["hour"]))
    if "minutes_per_tick" in body and e.s.mode != "hybrid":
        e.s.sim_minutes_per_tick = max(0.5, min(60.0, float(body["minutes_per_tick"])))
    return e.sim_clock()


@app.post("/api/reset")
def reset(_: str = Depends(demo)):
    old = H.engine
    old.stop()
    time.sleep(0.2)
    for sub in ("ledger", "keys"):
        shutil.rmtree(os.path.join(H.settings.data_dir, sub), ignore_errors=True)
    for f in ("local.db",):
        try:
            os.remove(os.path.join(H.settings.data_dir, f))
        except OSError:
            pass
    H.engine = Engine(H.settings, model=old.model)
    H.engine.start()
    return {"ok": True}


# ------------------------------------------------------------------ websocket
@app.websocket("/ws")
async def ws(sock: WebSocket):
    await sock.accept()
    last_seq = 0
    try:
        while True:
            e = E()
            data = await asyncio.get_running_loop().run_in_executor(None, e.overview)
            with e.lock:
                new = [f for f in e.feed if f["seq"] > last_seq][:50]
                last_seq = e.seq
            await sock.send_text(json.dumps({"type": "overview", "data": data, "feed": new[::-1]},
                                            default=lambda o: o.item() if hasattr(o, "item") else str(o), allow_nan=False))
            await asyncio.sleep(1.0)
    except (WebSocketDisconnect, RuntimeError):
        return


# ------------------------------------------------------------------ static UI
@app.get("/")
def index():
    return FileResponse(os.path.join(WEB_DIR, "index.html"))


if os.path.isdir(WEB_DIR):
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
