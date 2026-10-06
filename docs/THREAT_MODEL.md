# Threat model

## Assets

| Asset | Why it matters |
|---|---|
| Device identities and keys | Prove which device sent a message |
| The security event log | Evidence of what happened; a target for cover-up |
| Trust scores and quarantine state | Drive automated response |
| The lock and alarm actuators | Physical safety and security |

## Adversaries considered

| Adversary | Capability |
|---|---|
| Network attacker | Floods, scans, brute-forces PINs, replays or forges messages on the LAN |
| Rogue device | Joins the network claiming to be a device or as an unknown node |
| Host intruder | Gains write access to the monitoring host's local database or one ledger copy |
| Insider with admin token | Can approve recovery or quarantine — bounded by audit trail only |

## Mitigations

| Threat | Mitigation | Evidence |
|---|---|---|
| Spoofed identity | Per-device ECDSA keys enrolled on the ledger; signature verified at the gateway | `test_replay_and_spoofing_*` |
| Replay | Single-use nonce cache + ±30 s timestamp window | engine tests, evaluation |
| Rogue device | Unregistered IDs are quarantined at once; cannot be restored until enrolled | `test_rogue_device_*` |
| Flood / probing / brute force | Rules + adaptive baseline + ML; trust penalty; escalation by attack memory | evaluation, engine tests |
| Slow ("low-and-slow") attacks | Per-device per-hour baseline; ML | `test_stealth_surge_*` |
| Log tampering (edit / delete) | Hash of every record anchored on-chain; checker recomputes and compares; mismatch lowers trust | `test_local_log_tampering_*`, `test_deleting_*` |
| Ledger copy tampering | Hash links, proposer + quorum signatures against genesis keys, cross-node comparison; faulty node excluded and healed | `test_ledger.py` (incl. re-hash attack) |
| Unsafe automated response | Lock is fail-secure; recovery is administrator-gated and logged | `test_quarantine_blocks_commands_*` |
| Unauthorised admin actions | Admin token on every state-changing endpoint; localhost bind by default | `test_admin_endpoints_require_token` |

## Residual risks and limitations

- **Anchoring starts at commit time.** A record altered before it is hashed is not detected.
- **Validators share a machine.** A host compromise reaches all three copies and all keys. Separate machines (or hardware
  security modules) are needed for a real trust boundary. This prototype demonstrates tamper-evidence, not Byzantine
  fault tolerance.
- **Keys are PEM files** (`data/keys`, mode 0600). ESP32 flash encryption, secure boot or a secure element are required
  to protect device keys against physical access.
- **Unsigned ESP-1 firmware.** The gateway attests for it, so a compromised gateway can speak for ESP-1.
- **Trust-based quarantine is a denial-of-service lever.** Forged traffic could try to push a victim's trust down.
  Mitigations: replay and spoofing events are capped at HIGH, penalise the victim at 40 % of the normal weight, and
  never quarantine by themselves; the source is blocked instead. Log tampering *does* quarantine the implicated device
  (per the proposal), but that already requires host compromise.
- **Gateway-scoped blocking.** Traffic sent straight to a device's own web server cannot be filtered by the gateway;
  the response there is quarantine and alarm.
- **ML is trained on simulator data.** On real hardware it runs in shadow mode until retrained. Its robustness to an
  adaptive attacker is untested.
- **Default admin token for demos.** Set `TRUSTCHAIN_ADMIN_TOKEN` and keep the default localhost bind for anything real.
- **No transport security** between the engine and the ESP32 boards (plain HTTP on the LAN), matching the original design.
- The proposal's novelty claims are preliminary and have not been checked by a prior-art search.

## Reporting a vulnerability

See [`../SECURITY.md`](../SECURITY.md).
