#!/usr/bin/env bash
# check-no-auto-update.sh <image.qcow2>
#
# Offline (no boot) assertion that a built image cannot change itself: no unattended apt
# upgrade, and no automatic service restart after a manual one (issue #71).
#
# Why this is a CI gate and not just a build-time check: an auto-upgrade on a measured node
# restarts tapp-server (observed: a glibc upgrade restarting tapp-server + containerd +
# sysbox) -> the in-memory app signer rotates -> every on-chain node/service of every app on
# that node goes stale, with no operator action. The failure surfaces days later, far from
# the build. Running on the FINAL converted image also catches what an in-line build check
# cannot: a later apt step pulling unattended-upgrades back in as a Recommends.
#
# Checks:
#   1. apt-daily{,-upgrade}.{timer,service} masked (-> /dev/null)
#   2. unattended-upgrades purged (no /usr/bin/unattended-upgrade)
#   3. /etc/apt/apt.conf.d/20auto-upgrades sets every periodic knob to "0"
#   4. the EFFECTIVE needrestart mode is 'l' (list-only) — i.e. the last assignment across
#      needrestart.conf + conf.d/*.conf in read order, not merely "our drop-in says 'l'":
#      needrestart.conf ends with `foreach my $fn (sort <conf.d/*.conf>)`, so a later-sorting
#      drop-in silently wins.
#
# Usage: cvm/ci/check-no-auto-update.sh out-dev.qcow2
# Exit:  0 = all checks pass, 1 = a check failed, 2 = setup/mount error.

set -uo pipefail
export LIBGUESTFS_BACKEND=direct

IMG="${1:?usage: $0 <image.qcow2>}"
[ -f "$IMG" ] || { echo "image not found: $IMG" >&2; exit 2; }
command -v guestfish >/dev/null || { echo "guestfish is required" >&2; exit 2; }

# Converted images keep the rootfs on the cryptpilot LVM; a pre-convert (stage A) image is a
# plain partition. Try the converted layout first, fall back to the plain one.
MOUNT_CONVERTED='run
vgscan
vg-activate-all true
mount-ro /dev/cryptpilot/rootfs /'
MOUNT_PLAIN='run
mount-ro /dev/sda1 /'

# ONE guestfish run for everything: on the CI builder there is no /dev/kvm, so each libguestfs
# appliance boot costs minutes under TCG. `ll` prints symlink targets and `is-file` prints
# true/false without aborting on missing paths, so all the tolerant commands run first; the
# `cat`s go last, where an abort (missing file) costs nothing — the checks below then fail on
# the absent content, and the is-file flags say which file was missing.
CMDS='ll /etc/systemd/system/
is-file /usr/bin/unattended-upgrade
is-file /etc/apt/apt.conf.d/20auto-upgrades
is-file /etc/needrestart/conf.d/99-tapp-no-auto-restart.conf
cat /etc/apt/apt.conf.d/20auto-upgrades
cat /etc/needrestart/needrestart.conf
glob cat /etc/needrestart/conf.d/*.conf'

run() { printf '%s\n%s\n' "$1" "$CMDS" | guestfish --ro -a "$IMG" 2>&1; }

# The mount is probed by the same run: is-file only prints true/false once a rootfs is mounted.
LAYOUT=converted
OUT="$(run "$MOUNT_CONVERTED")"
if ! grep -qx 'true\|false' <<<"$OUT"; then
  LAYOUT=plain
  OUT="$(run "$MOUNT_PLAIN")"
  grep -qx 'true\|false' <<<"$OUT" || { echo "cannot mount a rootfs in $IMG" >&2; echo "$OUT" >&2; exit 2; }
fi
echo "==> $IMG: $LAYOUT layout"

fail=0
say_fail() { echo "  FAIL: $1"; fail=1; }

# 1. apt-daily* masked (-qF: unit names contain dots, which are ERE wildcards)
for u in apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service; do
  grep -qF "$u -> /dev/null" <<<"$OUT" \
    && echo "  ok: $u masked" \
    || say_fail "$u is NOT masked in /etc/systemd/system (auto-upgrade can still fire)"
done

# 2/3/4a. the three is-file results are the only bare true/false lines, in command order
readarray -t FLAGS < <(grep -x 'true\|false' <<<"$OUT")
[ "${FLAGS[0]:-}" = false ] \
  && echo "  ok: unattended-upgrades purged" \
  || say_fail "/usr/bin/unattended-upgrade still present (unattended-upgrades not purged)"
[ "${FLAGS[1]:-}" = true ] || say_fail "/etc/apt/apt.conf.d/20auto-upgrades missing"
[ "${FLAGS[2]:-}" = true ] || say_fail "/etc/needrestart/conf.d/99-tapp-no-auto-restart.conf missing"

# 3. every periodic knob off
for knob in Update-Package-Lists Download-Upgradeable-Packages Unattended-Upgrade AutocleanInterval; do
  grep -qE "APT::Periodic::$knob \"0\";" <<<"$OUT" \
    && echo "  ok: APT::Periodic::$knob = 0" \
    || say_fail "APT::Periodic::$knob is not \"0\" in 20auto-upgrades"
done

# 4. EFFECTIVE needrestart mode: last uncommented assignment wins (main conf, then sorted conf.d).
#    Checking our drop-in's content alone would pass even when a later-sorting drop-in overrides it.
EFFECTIVE="$(grep -oE "^\\\$nrconf\{restart\} *= *'.'" <<<"$OUT" | tail -1 | grep -oE "'.'")"
case "${EFFECTIVE:-none}" in
  "'l'") echo "  ok: effective needrestart mode = 'l' (list-only)" ;;
  none)  say_fail "no \$nrconf{restart} assignment in /etc/needrestart (needrestart would use its own default)" ;;
  *)     say_fail "effective needrestart mode is ${EFFECTIVE} — a later drop-in overrides list-only; services would auto-restart" ;;
esac

if [ "$fail" -ne 0 ]; then
  echo "==== raw guestfish output ===="
  echo "$OUT"
  echo "AUTO-UPDATE CHECK FAILED for $IMG (issue #71)" >&2
  exit 1
fi
echo "AUTO-UPDATE CHECK PASS: $IMG cannot upgrade or restart itself"
