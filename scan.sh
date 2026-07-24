#!/bin/sh
#
# hardenmac-scan — read-only AMOS / Atomic / SHAMOS infostealer indicator check for macOS
# ---------------------------------------------------------------------------------------
# I built this after a persistent Mac infostealer ran on my Mac — behavior consistent with
# credential-stealing and remote-access malware, though the specific family was not
# independently confirmed. Evidence shows it was present by April 3 and discovered June 6
# (~2 months). It disguised itself as com.apple.accountsd, relaunched about once a second,
# a hidden file containing my login password was found near it (a hidden ~/.pass file). My
# antivirus reported clean while persistence remained. This script checks for what I missed.
#
# WHAT THIS DOES:  read-only checks for KNOWN indicators of the AMOS/Atomic/SHAMOS family.
# WHAT IT NEVER DOES:  no network calls, no sudo, no writes, no deletions, no telemetry.
#   Read it before you run it. It is meant to be auditable in a couple of minutes — that is
#   the whole point. (AMOS itself spreads via "paste this command" lures; never trust a
#   security tool that phones home or pipes from curl into a shell.)
#
# USAGE:   sh scan.sh
# EXIT:    0 = no known indicators found   1 = suspicious item(s)   2 = known-bad item(s)
#
# A CLEAN RESULT IS NOT A GUARANTEE. This checks a limited set of documented indicators as of
# the date below; it cannot identify a malware family, prove a Mac is infected, or prove a Mac
# is clean. A hit flags a known indicator to investigate. A clean result means none of the
# indicators checked by this version were found; it does not prove the Mac is clean. These
# families rotate file names and infrastructure. Harden anyway.
#
# IOCs reviewed: 2026-06-15. Sources: Objective-See, Jamf, SentinelOne, BleepingComputer,
#   CrowdStrike, Field Effect, Huntress, iru.com, Rewterz. See iocs/ in the repo.
# License: MIT. No warranty. This is experience-based guidance, not professional advice.

IOC_DATE="2026-06-15"

# ---- output helpers (color only if stdout is a terminal) ------------------------------
if [ -t 1 ]; then
  C_RED='\033[0;31m'; C_YEL='\033[0;33m'; C_GRN='\033[0;32m'; C_DIM='\033[0;90m'; C_BLD='\033[1m'; C_RST='\033[0m'
else
  C_RED=''; C_YEL=''; C_GRN=''; C_DIM=''; C_BLD=''; C_RST=''
fi

findings_bad=0
findings_susp=0

hit_bad()  { findings_bad=$((findings_bad + 1));  printf "%s  [KNOWN-BAD]%s  %s\n" "$C_RED" "$C_RST" "$1"; [ -n "$2" ] && printf "%s              %s%s\n" "$C_DIM" "$2" "$C_RST"; }
hit_susp() { findings_susp=$((findings_susp + 1)); printf "%s  [SUSPICIOUS]%s %s\n" "$C_YEL" "$C_RST" "$1"; [ -n "$2" ] && printf "%s              %s%s\n" "$C_DIM" "$2" "$C_RST"; }
ok()       { printf "%s  [clear]%s     %s\n" "$C_GRN" "$C_RST" "$1"; }
section()  { printf "\n%s%s%s\n" "$C_BLD" "$1" "$C_RST"; }

HOME_DIR="${HOME:-/Users/$(id -un)}"

printf "${C_BLD}hardenmac-scan${C_RST}  ${C_DIM}(read-only · no network · no sudo · IOCs as of %s)${C_RST}\n" "$IOC_DATE"
printf "${C_DIM}Checking this account: %s${C_RST}\n" "$(id -un)"

# =======================================================================================
# LAYER 1 — LaunchDaemon / LaunchAgent persistence (highest-signal check)
# =======================================================================================
section "Layer 1 — Persistence (launchd items disguised as Apple processes)"

# 1a. Known-bad plist labels / paths
for plist in \
  "/Library/LaunchDaemons/com.finder.helper.plist" \
  "/Library/LaunchDaemons/com.apple.accountsd.helper.plist" \
  "$HOME_DIR/Library/LaunchAgents/com.finder.helper.plist" \
  "$HOME_DIR/Library/LaunchAgents/com.apple.accountsd.helper.plist"
do
  if [ -e "$plist" ]; then
    hit_bad "$plist" "Known AMOS persistence label mimicking an Apple service."
  fi
done

# 1b. Heuristic: a LaunchDaemon/Agent that runs a shell against a hidden home dotfile
#     AND sets KeepAlive (the relaunch loop). The KeepAlive is the discriminator: AMOS
#     uses it to respawn instantly (~1×/sec) when killed. Legit scheduled agents use
#     StartInterval / event triggers and do NOT KeepAlive a shell against a dotfile,
#     so this stays precise and avoids flagging normal power-user LaunchAgents.
#     Read-only: we only read plist text.
scan_plist_dir() {
  dir="$1"
  [ -d "$dir" ] || return 0
  for p in "$dir"/*.plist; do
    [ -e "$p" ] || continue
    # Pull a flat text view of the plist without modifying it.
    body=$(plutil -p "$p" 2>/dev/null || cat "$p" 2>/dev/null)
    [ -n "$body" ] || continue
    # Three conditions must ALL hold: shell invocation + hidden home dotfile + KeepAlive.
    if printf "%s" "$body" | grep -Eq '(/bin/(ba)?sh)' \
       && printf "%s" "$body" | grep -Eq '/Users/[^/]+/\.[A-Za-z0-9._-]+|<string>~?/\.' \
       && printf "%s" "$body" | grep -Eiq 'KeepAlive'
    then
      label=$(printf "%s" "$body" | grep -Eo 'com\.[A-Za-z0-9._-]+' | head -n1)
      hit_susp "$p" "Shell + hidden home dotfile + KeepAlive relaunch loop${label:+ (label: $label)} — matches AMOS loader behavior. Verify what it runs."
    fi
  done
}
scan_plist_dir "/Library/LaunchDaemons"
scan_plist_dir "/Library/LaunchAgents"
scan_plist_dir "$HOME_DIR/Library/LaunchAgents"

[ $((findings_bad + findings_susp)) -eq 0 ] && ok "No known-bad labels or AMOS-style loader plists found."

# =======================================================================================
# LAYER 2 — Known dropped / hidden files
# =======================================================================================
section "Layer 2 — Dropped & hidden files"
l2_start=$((findings_bad + findings_susp))

# $HOME_DIR expands inside double quotes; /tmp paths are absolute.
for path in \
  "$HOME_DIR/.helper" "$HOME_DIR/.mainhelper" "$HOME_DIR/.agent" \
  "$HOME_DIR/.pass" "$HOME_DIR/.logged" "/tmp/.pass" \
  "$HOME_DIR/Library/Application Support/.com.apple.accountsd/AccountsHelper" \
  "/tmp/starter" "/tmp/out.zip" "/tmp/helper" "/private/tmp/helper" \
  "/tmp/app.zip" "/tmp/apptwo.zip" "/tmp/appex.zip"
do
  if [ -e "$path" ]; then
    note="Known AMOS artifact."
    case "$path" in
      */.pass) note="AMOS caches the stolen login password here in PLAINTEXT — treat the password as compromised." ;;
      */.logged) note="AMOS marker file (often contains the string 'User10')." ;;
      *AccountsHelper) note="Known malicious infostealer implant path." ;;
    esac
    hit_bad "$path" "$note"
  fi
done
[ $((findings_bad + findings_susp)) -eq "$l2_start" ] && ok "None of the known dropped/hidden files are present."

# =======================================================================================
# LAYER 3 — Known C2 indicators (host file + live connections)
# =======================================================================================
section "Layer 3 — Known C2 indicators"
l3_start=$((findings_bad + findings_susp))

C2_LIST="45.94.47.145 45.94.47.147 45.94.47.204 92.246.136.14 laislivon.com wusetail.com systellis.com arkypc.com lakhov.com ouilov.com foto.gd mpasvw.com"

# 3a. /etc/hosts (read-only)
if [ -r /etc/hosts ]; then
  for ioc in $C2_LIST; do
    if grep -Fq "$ioc" /etc/hosts 2>/dev/null; then
      hit_bad "/etc/hosts contains $ioc" "Known AMOS C2 indicator pinned in your hosts file."
    fi
  done
fi

# 3b. Current outbound connections (read-only; lsof needs no sudo for your own procs)
conns=$(lsof -nP -i 2>/dev/null || true)
if [ -n "$conns" ]; then
  for ioc in $C2_LIST; do
    case "$ioc" in
      *.*[a-z]) match=$(printf "%s" "$conns" | grep -F "$ioc" || true) ;;  # domain
      *)        match=$(printf "%s" "$conns" | grep -F "$ioc" || true) ;;  # ip
    esac
    if [ -n "$match" ]; then
      hit_bad "Live connection to $ioc" "An active socket is talking to a known AMOS C2 indicator."
    fi
  done
fi
[ $((findings_bad + findings_susp)) -eq "$l3_start" ] && ok "No known C2 indicators in /etc/hosts or current connections. (Note: AMOS rotates infra — this list ages fast.)"

# =======================================================================================
# LAYER 4 — Trojanized crypto-wallet apps (signature check)
# =======================================================================================
section "Layer 4 — Crypto-wallet integrity"
l4_start=$((findings_bad + findings_susp))

for app in "/Applications/Ledger Live.app" "/Applications/Trezor Suite.app" "/Applications/Exodus.app"; do
  if [ -d "$app" ]; then
    if codesign -vv "$app" >/dev/null 2>&1; then
      ok "$app — code signature valid."
    else
      hit_susp "$app — signature INVALID or unsigned" "AMOS replaces wallet apps with trojanized builds. Reinstall from the vendor, and treat wallet seeds as exposed."
    fi
  fi
done
[ $((findings_bad + findings_susp)) -eq "$l4_start" ] && [ ! -d "/Applications/Ledger Live.app" ] && [ ! -d "/Applications/Trezor Suite.app" ] && [ ! -d "/Applications/Exodus.app" ] && ok "No targeted wallet apps installed."

# =======================================================================================
# LAYER 5 — Delivery-vector artifacts (shell history)
# =======================================================================================
section "Layer 5 — Delivery-vector traces (ClickFix / AI-tool paste lures)"
l5_start=$((findings_bad + findings_susp))

for hist in "$HOME_DIR/.zsh_history" "$HOME_DIR/.bash_history"; do
  [ -r "$hist" ] || continue
  # curl piped straight into a shell — the exact AMOS install pattern (incl. the Cursor/Claude-Code vector)
  if grep -Eq 'curl[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba)?sh' "$hist" 2>/dev/null; then
    line=$(grep -En 'curl[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba)?sh' "$hist" 2>/dev/null | head -n1)
    hit_susp "curl|bash pattern in $(basename "$hist")" "Found: ${line}. This is how AMOS/ClickFix gets run. Review what it fetched and from where."
  fi
  # osascript paired with password-piped sudo (-S)
  if grep -Eq 'osascript' "$hist" 2>/dev/null && grep -Eq 'sudo[[:space:]]+-S' "$hist" 2>/dev/null; then
    hit_susp "osascript + 'sudo -S' in $(basename "$hist")" "Password-piped privilege escalation via AppleScript — an AMOS technique. Worth investigating."
  fi
done
[ $((findings_bad + findings_susp)) -eq "$l5_start" ] && ok "No curl|bash or osascript+sudo -S traces in shell history."

# =======================================================================================
# RESULT
# =======================================================================================
printf "\n%s—— Result ——%s\n" "$C_BLD" "$C_RST"
if [ "$findings_bad" -gt 0 ]; then
  printf "%s%sKNOWN-BAD indicators found: %s%s\n" "$C_RED" "$C_BLD" "$findings_bad" "$C_RST"
  [ "$findings_susp" -gt 0 ] && printf "%sSuspicious items: %s%s\n" "$C_YEL" "$findings_susp" "$C_RST"
  printf "Assume every credential this machine has touched is compromised.\n"
  printf "Do not just delete the files — follow the full recovery checklist:\n"
  printf "  %shttps://hardenmac.com/checklist%s\n" "$C_BLD" "$C_RST"
  rc=2
elif [ "$findings_susp" -gt 0 ]; then
  printf "%s%sSuspicious items found: %s%s (no confirmed known-bad indicators)\n" "$C_YEL" "$C_BLD" "$findings_susp" "$C_RST"
  printf "Investigate each above. If in doubt, work through the recovery checklist:\n"
  printf "  %shttps://hardenmac.com/checklist%s\n" "$C_BLD" "$C_RST"
  rc=1
else
  printf "%s%sNo known AMOS/Atomic/SHAMOS indicators found.%s\n" "$C_GRN" "$C_BLD" "$C_RST"
  printf "%sThis checks documented indicators as of %s. These families rotate —\n" "$C_DIM" "$IOC_DATE"
  printf "a clean result means none of the indicators checked were found; it does not prove the Mac is clean.%s\n" "$C_RST"
  printf "Harden next so the next one has a harder time:  %shttps://hardenmac.com/checklist%s\n" "$C_BLD" "$C_RST"
  rc=0
fi
exit "$rc"
