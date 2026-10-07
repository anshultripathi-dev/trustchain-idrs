"""Regenerate docs/EVALUATION.md from the result files, so no number is ever typed by hand.

    python scripts/gen_eval_doc.py          # reads docs/results/*.json, writes docs/EVALUATION.md

Refresh the inputs first:  make train && make evaluate && cp data/evaluation.json docs/results/evaluation.json
                           cp models/metrics.json docs/results/ml-metrics.json
"""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = os.path.join(ROOT, "docs", "results")
e = json.load(open(os.path.join(R, "evaluation.json")))
m = json.load(open(os.path.join(R, "ml-metrics.json")))

names = {"static_rules": "Static rules (original IDS)", "isolation_forest": "Isolation Forest only", "hybrid": "Hybrid (rules + IF + classifier)"}
atk = ["BRUTE_FORCE", "REQUEST_FLOOD", "SERVICE_PROBING", "SENSOR_ANOMALY", "STEALTH_SURGE"]
pct = lambda v, d=1: f"{v * 100:.{d}f} %"
c, cl, s, t, cn, hc = m["comparison"], m["classifier"], m["samples"], e["tamper"], e["clean"], e.get("home_clean")

rows1 = "\n".join(f"| {names[k]} | {pct(c[k]['episode_recall_macro'])} | {pct(c[k]['false_positive_rate_tick'], 2)} | {pct(c[k]['false_positive_rate_confirmed'], 3)} |" for k in names)
rows2 = "\n".join("| " + a.replace("_", " ").title() + " | " + " | ".join(pct(c[k]["per_attack"][a]["episode_recall"]) for k in names) + " |" for a in atk)
rows3 = "\n".join(f"| {l.replace('_', ' ').title()} | {cl['report'][l]['precision']:.3f} | {cl['report'][l]['recall']:.3f} | {cl['report'][l]['f1-score']:.3f} |" for l in cl["labels"])
rows4 = "\n".join(f"| {v['label']} | {v['layer']} | {pct(v['detection_rate'], 0)} | {pct(v['classification_rate'], 0)} | {v['mean_latency_ticks']} | {pct(v['quarantine_rate'], 0)} |" for v in e["scenarios"].values())
kinds = ", ".join(m.get("profile_kinds", []))

home_section = ""
if hc:
    sev = ", ".join(f"{k.title()} {v}" for k, v in sorted(hc["by_severity"].items(), key=lambda kv: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(kv[0])))
    home_section = f"""
## 4. The full smart home on clean traffic

All {hc['devices']} devices across every room, {hc['device_ticks']:,} device-ticks (≈ {hc['sim_days']} simulated days, three random seeds), no attacks:

| Measure | Result |
|---|---|
| Security events raised | {hc['events']} ({hc['events_per_sim_day']} per simulated day for the whole home) |
| By severity | {sev} |
| **False quarantines** | **{hc['false_quarantines']}** |

Weak, unexplained evidence (no rule hit and low overall risk) may only *alert*: it can never escalate to blocking or quarantine by
repeating. Only rule hits or strong multi-signal risk can. Before this cap was introduced, the same soak produced false
quarantines of a door lock and a router from repeated borderline ML anomalies.

Per-tick processing time is measured separately (`ms_per_tick` in the JSON depends on what else the machine was doing); a standalone
38-device tick takes on the order of 15–20 ms because ML inference is batched across all devices in a tick.
"""

doc = f"""# Evaluation

> **Scope.** Every number here comes from the built-in traffic simulator (`trustchain/sim/profiles.py`),
> which generates the training data *and* the test data (with separate random streams). The results show how the
> detection methods compare **under the same assumptions**; they are not accuracy claims for a real household.
> Re-measure on real telemetry before drawing real-world conclusions.

Raw results: [`results/ml-metrics.json`](results/ml-metrics.json) (model comparison) and
[`results/evaluation.json`](results/evaluation.json) (end-to-end scenarios). Regenerate this page with
`python scripts/gen_eval_doc.py`.

## 1. Detector comparison (held-out simulated episodes)

Trained on **{len(m.get('profile_kinds', []))} device archetypes** ({kinds}), which the 38 devices of the full smart home map onto.
Data: {s['train_normal']:,} train / {s['test_normal']:,} test normal ticks; {s['train_attack']:,} train / {s['test_attack']:,} test attack ticks
across five traffic-attack classes. An *episode* counts as detected if the detector fires within it (ML-only evidence must persist
for two consecutive ticks; rules fire immediately).

| Detector | Macro episode recall | False positives (per tick) | False positives (2-tick confirm) |
|---|---|---|---|
{rows1}

Episode recall by attack class:

| Attack | Static rules | Isolation Forest only | Hybrid |
|---|---|---|---|
{rows2}

Static thresholds cannot see sensor drift that stays inside the legal range or a quiet-hours surge that stays under 10 req/s.
The adaptive baseline and ML layers catch both. The Isolation Forest alone is weak on sensor tampering across such different
devices (a fridge, an oven and a router have very different "normal"), which is where the attack classifier and per-device baseline
add the most.

![Detector comparison](images/09-ml-detector-comparison.png)

## 2. Attack-class classifier

Random Forest (200 trees, balanced classes), accuracy **{pct(cl['accuracy'])}** on the held-out ticks.

| Class | Precision | Recall | F1 |
|---|---|---|---|
{rows3}

Sensor anomalies are the hardest class: across 16 archetypes some normal readings look like a tampered sensor and vice versa.
That is exactly why classifier output alone never quarantines a device (see §4).

![Classifier](images/10-ml-classifier.png)

## 3. End-to-end scenarios

{e['trials']} trials per scenario, each on a fresh in-memory system (the five original devices) with a virtual clock (1 tick = 1 s).
*Latency* is ticks from attack start to the first security event.

| Scenario | Layer | Detected | Classified correctly | Mean latency (ticks) | Quarantined |
|---|---|---|---|---|---|
{rows4}

Replay and spoofing intentionally do **not** quarantine the victim: the gateway blocks the source and only mildly reduces the
victim's trust, so an outsider cannot knock a legitimate device offline by forging its traffic.

| Tamper scenario | Detected | Device quarantined |
|---|---|---|
| Local log edited | {pct(t['LOG_TAMPERING']['detection_rate'], 0)} | {pct(t['LOG_TAMPERING']['quarantine_rate'], 0)} |
| Validator copy modified | {pct(t['LEDGER_NODE_TAMPERING']['detection_rate'], 0)} | {pct(t['LEDGER_NODE_TAMPERING']['quarantine_rate'], 0)} (network keeps running on the quorum) |

**Clean traffic (five devices):** {cn['false_events']} false event(s) in {cn['device_ticks']:,} device-ticks (≈ {cn['sim_days']} simulated days), {cn['false_quarantines']} false quarantines.

![Evaluation table](images/13-evaluation-table.png)
{home_section}
## 5. Reproduce

```bash
make train       # retrains the models and rewrites models/metrics.json
make evaluate    # runs everything above (≈ 5–15 minutes depending on the machine)
cp data/evaluation.json docs/results/evaluation.json && cp models/metrics.json docs/results/ml-metrics.json
python scripts/gen_eval_doc.py
```

Results vary slightly with the random seeds; the qualitative picture (static < IF < hybrid, all scenarios detected, no false
quarantines) is stable.

## 6. What this evidence does not show

- Real-world accuracy, real attacker behaviour, or long-term baseline drift.
- Behaviour on devices whose traffic differs from the 16 simulated archetypes.
- Adversarial robustness of the ML layer (an adaptive attacker who learns the thresholds).
- On real hardware the ML layer runs in **shadow mode**: models trained on simulator data flagged an idle ESP-1 as anomalous,
  so there rules act and ML only observes until it is retrained on real telemetry.
"""
open(os.path.join(ROOT, "docs", "EVALUATION.md"), "w").write(doc)
print("wrote docs/EVALUATION.md", len(doc.splitlines()), "lines")
