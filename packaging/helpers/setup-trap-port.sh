#!/bin/sh
# Explicit administrator action only; never invoked by package lifecycle hooks.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/syno/bin:/usr/syno/sbin
export PATH
package=HardwareMonitor
target=/var/packages/HardwareMonitor/target
fail() { echo "ERROR: $*" >&2; exit 1; }
usage() { echo "Usage: $0 [enable|status|disable]"; }
action=${1:-enable}
test "$#" -le 1 || { usage; exit 1; }
case "$action" in enable|status|disable) ;; *) usage; exit 1 ;; esac
test "$(id -u)" = 0 || fail 'Run this script as root (sudo).'
for tool in setcap getcap readlink stat; do
    command -v "$tool" >/dev/null 2>&1 || fail "Required tool not found: $tool"
done
physical=$(readlink -f "$target") || fail 'Package target is unavailable.'
case "$physical" in
    /volume[0-9]*/@appstore/HardwareMonitor)
        volume=${physical#/volume}; volume=${volume%%/*}
        case "$volume" in ''|*[!0-9]*) fail 'Unexpected package volume.' ;; esac ;;
    *) fail 'Unexpected package target; refusing to change another path.' ;;
esac
binary="$physical/bin/hardware-monitor"
test "$(readlink -f "$binary")" = "$binary" || fail 'Executable path contains a symlink; refusing to leave the package target.'
test -f "$binary" && test ! -L "$binary" && test -x "$binary" || fail 'Expected a regular package executable, not a symlink.'
test "$(stat -c '%h' "$binary")" = 1 || fail 'Refusing an executable with multiple hard links.'
if test "$action" = status; then
    if setcap -v cap_net_bind_service=ep "$binary"; then
        echo 'Port capability is configured. Check actual receiver status in Hardware Monitor.'
    else
        echo 'Port capability is missing or differs. Run this script with enable.' >&2
        exit 1
    fi
    exit 0
fi
command -v synopkg >/dev/null 2>&1 || fail 'DSM package manager not found.'
# Stop via DSM so it retains control of the package identity on restart.
synopkg stop "$package" || fail 'Package stop failed; no permissions changed.'
if test "$action" = enable; then
    chown root:HardwareMonitor "$binary"
    chmod 0750 "$binary"
    setcap cap_net_bind_service=ep "$binary" || fail 'Capability setup failed; package remains stopped.'
    setcap -v cap_net_bind_service=ep "$binary" || fail 'Capability verification failed; package remains stopped.'
else
    if test -n "$(getcap "$binary")"; then
        setcap -r "$binary" || fail 'Capability removal failed; package remains stopped.'
    fi
    chown HardwareMonitor:HardwareMonitor "$binary"
    chmod 0755 "$binary"
fi
synopkg start "$package" || fail 'Package restart failed; inspect the package service log.'
echo 'Done. Service runs as the package user. Check trap receiver status in Hardware Monitor.'
if test "$action" = enable; then
    echo 'If a package update replaces the executable, run enable again.'
fi
