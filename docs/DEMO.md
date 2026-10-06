# Demonstration guide

A guided walk through the whole closed loop. Takes about three minutes. The *Attack lab* page runs
everything in simulation; the last section covers real hardware.

Start the system (`make run`), open <http://127.0.0.1:8000>, and use the admin token (`admin` by default) when asked.

## Simulated walkthrough

| # | Do this | Watch for |
|---|---|---|
| 1 | **Attack lab → Brute-force PIN** on ESP-1 | Risk spikes on *Overview*; first event is **HIGH** (source blocked, trust ↓); the repeat is escalated to **CRITICAL** by attack memory → ESP-1 is **quarantined** and the simulated ESP-2 lights red and buzzes. The lock stays fail-secure. |
| 2 | **Threats** → open the newest event | Local record and on-chain hash side by side → **ledger verified**. |
| 3 | **Attack lab → Edit latest event in local DB**, then **Run integrity check** | Hash **MISMATCH**, an `AUDIT_TAMPERING` event, trust penalty. *Repair record from ledger* restores it. |
| 4 | **Attack lab → Modify a block on validator node-2** | **Ledger** shows node-2 *FAILED AUDIT* while the chain keeps committing on the 2-of-3 quorum. **Heal** repairs it. |
| 5 | Set the clock to **Night 02:00**, launch **Low-and-slow surge** | ~6 req/s never crosses the static threshold (10) but is a many-σ outlier for that hour — the adaptive baseline and ML flag it. |
| 6 | **Response & Recovery** → *Run security verification* once the attack ends, then *Approve & restore* | Both steps are ledger transactions; the alarm clears after the last device is released. |
| 7 | **Devices → Gateway commands**: send a command from a quarantined device | **BLOCKED**, with the reason. Try `unlock` from a low-trust device too. |
| 8 | **Replay**, **Spoofing**, **Rogue device** scenarios | Rejected at the gateway; only the rogue device is quarantined. The victim of a forged message is not. |

![Overview](images/01-overview.png)

## On real hardware (hybrid mode)

With both boards connected ([`HARDWARE.md`](HARDWARE.md)):

1. Type **three or more wrong PINs** on the keypad within 30 seconds.
2. Watch **Devices → ESP-1**: `BRUTE_FORCE` HIGH, trust 100 → 85. Keep going and the repeat escalates to CRITICAL and
   quarantines ESP-1; the real ESP-2 shows the alert on its LCD, lights the red LED and sounds the buzzer.
3. Stop entering PINs. After ~8 clean seconds, run the verification on **Response & Recovery** and approve the
   restore; ESP-2 returns to the green LED.
4. **Test alarm / Test safe** on the same page exercise the physical node without an attack.

## Tips

- Everything is logged to the ledger; the **Ledger** page shows each step as a signed block.
- *Reset demo* (Attack lab) wipes the ledger, keys and local log and starts a fresh chain.
- A tall browser window shows more of each page; the screenshots in `docs/images/` were captured at 1600 px wide, 2× scale.
