# Changelog

Each new campaign adds indicators here. The date stamps are the point — they
tell you (and a reader, and a search engine) how current the IOC set is.

## 2026-06-15 — initial release
- Five-layer check for the AMOS / Atomic / SHAMOS family:
  1. launchd persistence (known labels + `KeepAlive` loader heuristic)
  2. dropped/hidden files (`~/.pass`, `~/.helper`, `~/.agent`, `~/.logged`, staged `/tmp` archives, `AccountsHelper` implant)
  3. C2 indicators in `/etc/hosts` and live connections
  4. crypto-wallet signature integrity (Ledger Live, Trezor Suite, Exodus)
  5. delivery-vector traces in shell history (`curl | bash`, `osascript` + `sudo -S`)
- IOC corpus compiled from public reporting by Objective-See, Jamf Threat Labs,
  SentinelOne, BleepingComputer, CrowdStrike, Field Effect, Huntress, iru.com, Rewterz.
- Read-only, no network calls, no sudo, no writes.
