# hardenmac-scan

**A read-only check for AMOS / Atomic / SHAMOS infostealer indicators on macOS.**

My Mac was hit by a persistent infostealer — behavior consistent with credential-stealing and remote-access malware, though the specific family was not independently confirmed. Evidence shows it was present by April 3 and discovered June 6 — roughly two months. It disguised itself as `com.apple.accountsd`, relaunched roughly once a second, and a hidden file containing my login password was found near the malicious components (a hidden `~/.pass` file). My antivirus reported clean while persistence remained. This script checks for what I missed.

**What it can't do:** it checks a limited set of known indicators — it **cannot identify a malware family, prove a Mac is infected, or prove a Mac is clean.** A hit flags a known indicator to investigate. A clean result means none of the indicators checked by this version were found. It does not prove the Mac is clean.

---

## What it does

One shell script. It checks five layers for **known** indicators of the AMOS/Atomic/SHAMOS family:

1. **Persistence** — LaunchDaemons/Agents disguised as Apple services (`com.apple.accountsd.helper`, `com.finder.helper`), plus the AMOS loader signature (a shell run against a hidden home dotfile with a `KeepAlive` relaunch loop).
2. **Dropped files** — the known hidden artifacts (`~/.pass`, `~/.helper`, `~/.agent`, `~/.logged`, staged `/tmp` archives, the `AccountsHelper` implant).
3. **C2 indicators** — known infrastructure in `/etc/hosts` and your current network connections.
4. **Crypto-wallet integrity** — signature check on Ledger Live, Trezor Suite, and Exodus (AMOS replaces these with trojanized builds).
5. **Delivery-vector traces** — `curl … | bash` and `osascript` + `sudo -S` patterns in your shell history (the ClickFix / AI-tool paste lure, including the documented Cursor + Claude Code vector).

## What it never does

- **No network calls.** It does not phone home, send telemetry, or download anything. (AMOS itself spreads via "paste this command" lures — never trust a security tool that talks to the internet.)
- **No `sudo`.** Detection runs entirely as your user.
- **No writes, no deletions.** It reports what it finds. It does not "clean" anything — auto-removal on a tool like this is how you lose evidence and break your system. If it finds something, you follow the recovery checklist.

It is ~200 lines of POSIX `sh`. **Read it before you run it** — that's the whole point.

## How to run it

```sh
# 1. Download scan.sh
# 2. READ IT (it's short and commented)
# 3. Run it:
sh scan.sh
```

Do **not** pipe it from the internet into a shell (`curl ... | sh`). That is the exact pattern the malware uses. Download it, read it, then run it. Modeling safe behavior is the point.

## What the result means

| Exit | Meaning |
|------|---------|
| `0`  | No known indicators found. **This is not a guarantee** — a clean result means none of the indicators checked by this version were found; it does not prove the Mac is clean. These families rotate file names and infrastructure constantly. |
| `1`  | Suspicious item(s) — investigate each. Often a false-positive worth ruling out. |
| `2`  | Known-bad indicator(s) found. Treat the relevant accounts, sessions, and credentials as potentially exposed, move recovery to a trusted device, and begin the review and rotation process. |

A clean result is the moment to **harden**, not relax: <https://hardenmac.com/checklist>

## Why "clean" still mattered to me

My antivirus showed a green dashboard while the persistence remained installed. The root-level persistence was still installed and one item was still running as root when I finally audited it by hand. A reassuring result without transparent scope can create false confidence. This script states exactly what it checks and what it cannot establish.

## Indicators & sources

IOCs are versioned in [`iocs/`](iocs/) and dated. Reviewed **2026-06-15**. Compiled from public reporting by Objective-See, Jamf Threat Labs, SentinelOne, BleepingComputer, CrowdStrike, Field Effect, Huntress, iru.com, and Rewterz. Each new campaign adds to the same corpus and the changelog — so this one file gets more complete over time.

## License & disclaimer

MIT. No warranty. This is **experience-based** guidance from someone who survived an infection — not professional security advice or a guarantee of safety. It reduces uncertainty; it does not "protect" or "prevent."
