#!/bin/sh
set -eu
: "${SYNOPKG_TEMP_LOGFILE:?DSM wizard output path is required}"

# productversion includes the patch release, unlike the major/minor variables.
# Read trusted DSM metadata as text, without executing it.
dsm_version=$(sed -n 's/^productversion="\([0-9.]*\)"$/\1/p' /etc.defaults/VERSION)
case "$dsm_version" in
    ''|*[!0-9.]*) echo 'Cannot determine DSM wizard version.' >&2; exit 1 ;;
    *.*) ;;
    *) echo 'Invalid DSM version.' >&2; exit 1 ;;
esac
major=${dsm_version%%.*}
rest=${dsm_version#*.}
minor=${rest%%.*}
patch=${rest#*.}
[ "$patch" != "$rest" ] || patch=0
case "$major:$minor:$patch" in
    *..*|:*|*::*|*:|*[!0-9:]*) echo 'Invalid DSM version.' >&2; exit 1 ;;
esac

if [ "$major" -gt 7 ] || { [ "$major" -eq 7 ] && { [ "$minor" -gt 2 ] || { [ "$minor" -eq 2 ] && [ "$patch" -ge 2 ]; }; }; }; then
    cat > "$SYNOPKG_TEMP_LOGFILE" <<'HARDWARE_MONITOR_WIZARD'
__MODERN_WIZARD__
HARDWARE_MONITOR_WIZARD
else
    cat > "$SYNOPKG_TEMP_LOGFILE" <<'HARDWARE_MONITOR_WIZARD'
__LEGACY_WIZARD__
HARDWARE_MONITOR_WIZARD
fi
