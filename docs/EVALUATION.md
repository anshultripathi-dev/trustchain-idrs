# Evaluation

> **Scope.** Every number here comes from the built-in traffic simulator (`trustchain/sim/profiles.py`),
> which generates the training data *and* the test data (with separate random streams). The results show how the
> detection methods compare **under the same assumptions**; they are not accuracy claims for a real household.
> Re-measure on real telemetry before drawing real-world conclusions.

Raw results: [`results/ml-metrics.json`](results/ml-metrics.json) (model comparison) and
[`results/evaluation.json`](results/evaluation.json) (end-to-end scenarios).

## 1. Detector comparison (held-out simulated episodes)

Data: 11,520 train / 8,640 test normal ticks; 5,400 train / 8,100 test attack ticks
across five traffic-attack classes and five device profiles. An *episode* counts as detected if the detector fires
within it (ML-only evidence must persist for two consecutive ticks; rules fire immediately).

| Detector | Macro episode recall | False positives (per tick) | False positives (2-tick confirm) |
|---|---|---|---|
| Static rules (original IDS) | 64.0 % | 0.01 % | 0.01 % |
| Isolation Forest only | 91.3 % | 0.73 % | 0.02 % |
| Hybrid (rules + IF + classifier) | 100.0 % | 0.78 % | 0.03 % |

Episode recall by attack class:

| Attack | Static rules | Isolation Forest only | Hybrid |
|---|---|---|---|
| Brute Force | 100.0 % | 100.0 % | 100.0 % |
| Request Flood | 100.0 % | 100.0 % | 100.0 % |
| Service Probing | 100.0 % | 100.0 % | 100.0 % |
| Sensor Anomaly | 20.0 % | 56.7 % | 100.0 % |
| Stealth Surge | 0.0 % | 100.0 % | 100.0 % |

Static thresholds cannot see sensor drift that stays under 40 °C or a quiet-hours surge that stays under
10 req/s. The adaptive baseline and ML layers catch both. The Isolation Forest alone adds recall at the cost of
~0.7 % raw false positives, which the two-tick confirmation brings down to ~0.02–0.03 %.

![Detector comparison](images/09-ml-detector-comparison.png)

## 2. Attack-class classifier

Random Forest (200 trees, balanced classes), accuracy **99.8 %** on the held-out ticks.

| Class | Precision | Recall | F1 |
|---|---|---|---|
| Normal | 0.999 | 0.998 | 0.998 |
| Brute Force | 1.000 | 1.000 | 1.000 |
| Request Flood | 1.000 | 1.000 | 1.000 |
| Service Probing | 1.000 | 1.000 | 1.000 |
| Sensor Anomaly | 0.988 | 0.995 | 0.991 |
| Stealth Surge | 1.000 | 1.000 | 1.000 |

The few errors are borderline sensor readings between "normal" and "sensor anomaly".

![Classifier](images/10-ml-classifier.png)

## 3. End-to-end scenarios

3 trials per scenario, each on a fresh in-memory system with a virtual clock (1 tick = 1 s).
*Latency* is ticks from attack start to the first security event.

| Scenario | Layer | Detected | Classified correctly | Mean latency (ticks) | Quarantined |
|---|---|---|---|---|---|
| Brute-force PIN | traffic | 100.0 % | 100.0 % | 1.0 | 100.0 % |
| Request flood | traffic | 100.0 % | 100.0 % | 1.0 | 100.0 % |
| Service probing | traffic | 100.0 % | 100.0 % | 1.0 | 100.0 % |
| Sensor manipulation | traffic | 100.0 % | 100.0 % | 1.0 | 100.0 % |
| Low-and-slow surge | traffic | 100.0 % | 100.0 % | 2.0 | 100.0 % |
| Replay attack | crypto | 100.0 % | 100.0 % | 1.0 | 0.0 % |
| Identity spoofing | crypto | 100.0 % | 100.0 % | 1.0 | 0.0 % |
| Rogue device joins | crypto | 100.0 % | 100.0 % | 1.0 | 100.0 % |

Replay and spoofing intentionally do **not** quarantine the victim: the gateway blocks the source and only
mildly reduces the victim's trust, so an outsider cannot knock a legitimate device offline by forging its traffic.

| Tamper scenario | Detected | Device quarantined |
|---|---|---|
| Local log edited | 100.0 % | 100.0 % |
| Validator copy modified | 100.0 % | 0.0 % (network keeps running on the quorum) |

**Clean traffic:** 1 false event(s) in 6,000 device-ticks (≈ 4.17 simulated days),
0 false quarantines.

![Evaluation table](images/13-evaluation-table.png)

## 4. Reproduce

```bash
make train       # retrains the models and rewrites models/metrics.json
make evaluate    # runs the scenarios (about 5 minutes for 3 trials)
```

`.venv/bin/python scripts/evaluate.py 5` runs five trials per scenario. Results vary slightly with
the random seeds; the qualitative picture (static < IF < hybrid, all scenarios detected) is stable.

## 5. What this evidence does not show

- Real-world accuracy, real attacker behaviour, or long-term baseline drift.
- Behaviour on devices whose traffic differs from the five simulated profiles.
- Adversarial robustness of the ML layer (an adaptive attacker who learns the thresholds).
- On real hardware the ML layer runs in **shadow mode**: models trained on simulator data flagged an idle
  ESP-1 as anomalous, so there rules act and ML only observes until it is retrained on real telemetry.
