#!/usr/bin/env bash
# check-no-auto-update.sh <image.qcow2>
#
# Offline (no boot) assertion that a built image cannot change itself: no unattended apt
# upgrade, and no automatic service restart after a manual one (issue #71).
#
# Why this is a CI gate and not just a build step: an auto-upgrade on a measured node
# restarts tapp-server -> the in-memory app signer rotates -> every on-chain node/service
# of every app on that node goes stale, with no operator action; and an auto kernel/initrd
# upgrade changes RTMR + kernel_cmdline, invalidating the image's attestation reference
# values. Both failures surface days later, far from the build that caused them.
#
# Checks (on the final, converted image — so it also catches a convert-time regression):
#   1. apt-daily{,-upgrade}.{timer,service} masked (-> /dev/null)
#   2. unattended-upgrades purged (no /usr/bin/unattended-upgrade)
#   3. /etc/apt/apt.conf.d/20auto-upgrades sets every periodic knob to "0"
#   4. needrestart drop-in present and set to list-only ($nrconf{restart} = 'l')
#
# Usage: cvm/ci/check-no-auto-update.sh out-dev.qcow2
# Exit:  0 = all checks pass, 1 = a check failed, 2 = setup/mount error.

set -uo pipefail
export LIBGUESTFS_BACKEND=direct

IMG="${1:?usage: $0 <image.qcow2>}"
[ -f "$IMG" ] || { echo "image not found: $IMG" >&2; exit 2; }
command -v guestfish >/dev/null || { echo "guestfish is required" >&2; exit 2; }

# Converted images keep the rootfs on the cryptpilot LVM; a pre-convert (stage A) image is
# a plain partition. Try the converted layout first, fall back to the plain one.
MOUNT_CONVERTED='run
vgscan
vg-activate-all true
mount-ro /dev/cryptpilot/rootfs /'
MOUNT_PLAIN='run
mount-ro /dev/sda1 /'

gf() { # gf <mount-preamble> <commands...>  -> stdout+stderr of the guestfish run
  printf '%s\n%s\n' "$1" "$2" | guestfish --ro -a "$IMG" 2>&1
}

MOUNT="$MOUNT_CONVERTED"
if ! gf "$MOUNT" 'is-dir /etc' | grep -qx true; then
  MOUNT="$MOUNT_PLAIN"
  gf "$MOUNT" 'is-dir /etc' | grep -qx true || { echo "cannot mount a rootfs in $IMG" >&2; exit 2; }
  echo "==> $IMG: plain (pre-convert) layout"
else
  echo "==> $IMG: converted (cryptpilot) layout"
fi

# One pass for everything: `ll` shows symlink targets (tolerant of missing entries, unlike
# readlink which aborts the guestfish script), is-file prints true/false, cat prints content.
OUT="$(gf "$MOUNT" 'll /etc/systemd/system/
is-file /usr/bin/unattended-upgrade
is-file /etc/apt/apt.conf.d/20auto-upgrades
is-file /etc/needrestart/conf.d/00-tapp-no-auto-restart.conf')"

fail=0
say_fail() { echo "  FAIL: $1"; fail=1; }

# 1. apt-daily* masked
for u in apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service; do
  grep -qE "$u -> /dev/null" <<<"$OUT" \
    && echo "  ok: $u masked" \
    || say_fail "$u is NOT masked in /etc/systemd/system (auto-upgrade can still fire)"
done

# 2. unattended-upgrades gone. The three is-file results are the only bare true/false lines
readarray -t FLAGS < <(grep -x 'true\|false' <<<"$OUT")
# FLAGS = (unattended-upgrade, 20auto-upgrades, needrestart drop-in) in command order
[ "${FLAGS[0]:-}" = false ] \
  && echo "  ok: unattended-upgrades purged" \
  || say_fail "/usr/bin/unattended-upgrade still present (unattended-upgrades not purged)"

# 3 + 4. config files present, then their content
if [ "${FLAGS[1]:-}" = true ] && [ "${FLAGS[2]:-}" = true ]; then
  CONF="$(gf "$MOUNT" 'cat /etc/apt/apt.conf.d/20auto-upgrades
cat /etc/needrestart/conf.d/00-tapp-no-auto-restart.conf')"
  for knob in Update-Package-Lists Download-Upgradeable-Packages Unattended-Upgrade; do
    grep -qE "APT::Periodic::$knob \"0\";" <<<"$CONF" \
      && echo "  ok: APT::Periodic::$knob = 0" \
      || say_fail "APT::Periodic::$knob is not \"0\" in 20auto-upgrades"
  done
  grep -qE "^\\\$nrconf\{restart\} *= *'l';" <<<"$CONF" \
    && echo "  ok: needrestart = list-only" \
    || say_fail "needrestart drop-in does not set \$nrconf{restart} = 'l' (services would auto-restart)"
else
  [ "${FLAGS[1]:-}" = true ] || say_fail "/etc/apt/apt.conf.d/20auto-upgrades missing"
  [ "${FLAGS[2]:-}" = true ] || say_fail "/etc/needrestart/conf.d/00-tapp-no-auto-restart.conf missing"
fi

if [ "$fail" -ne 0 ]; then
  echo "==== raw guestfish output ===="
  echo "$OUT"
  echo "AUTO-UPDATE CHECK FAILED for $IMG (issue #71)" >&2
  exit 1
fi
echo "AUTO-UPDATE CHECK PASS: $IMG cannot upgrade or restart itself"
