# hardenmac-scan

**A read-only check for AMOS / Atomic / SHAMOS infostealer indicators on macOS.**

My Mac ran this exact malware for about three months. It disguised itself as `com.apple.accountsd`, relaunched roughly once a second, wrote my login password to `~/.pass`, and my antivirus reported clean the entire time. This script checks for what I missed.

---

## What it does

One shell script. It checks five layers for **known** indicators of the AMOS/Atomic/SHAMOS family:

1. **Persistence** — LaunchDaemons/Agents disguised as Apple services (`com.apple.accountsd.helper`, `com.finder.helper`), plus the AMOS loader signature (a shell run against a hidden home dotfile with a `KeepAlive` relaunch loop).
2. **Dropped files** — the known hidden artifacts (`~/.pass`, `~/.helper`, `~/.agent`, `~/.logged`, staged `/tmp` archives, the `AccountsHelper` backdoor implant).
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
| `0`  | No known indicators found. **This is not a guarantee** — these families rotate file names and infrastructure constantly. It lowers the odds; it does not prove you're clean. |
| `1`  | Suspicious item(s) — investigate each. Often a false-positive worth ruling out. |
| `2`  | Known-bad indicator(s) found. Treat every credential this machine has touched as compromised and work through recovery. |

A clean result is the moment to **harden**, not relax: <https://hardenmac.com/checklist>

## Why "clean" still mattered to me

My antivirus showed a green dashboard the whole time I was infected. The root-level persistence was still installed and one item was still running as root when I finally audited it by hand. Tools that say "you're fine" are exactly how this stuff dwells for months. This script tells you what it actually checked and what it can't promise.

## Indicators & sources

IOCs are versioned in [`iocs/`](iocs/) and dated. Reviewed **2026-06-15**. Compiled from public reporting by Objective-See, Jamf Threat Labs, SentinelOne, BleepingComputer, CrowdStrike, Field Effect, Huntress, iru.com, and Rewterz. Each new campaign adds to the same corpus and the changelog — so this one file gets more complete over time.

## License & disclaimer

MIT. No warranty. This is **experience-based** guidance from someone who survived an infection — not professional security advice or a guarantee of safety. It reduces uncertainty; it does not "protect" or "prevent."
