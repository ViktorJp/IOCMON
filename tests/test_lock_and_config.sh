#!/bin/sh
# Runs the stop, lock owner and cron exception code from iocmon.sh.
# Usage: tests/test_lock_and_config.sh [path/to/iocmon.sh]
S="$(cd "$(dirname "${1:-iocmon.sh}")" && pwd)/$(basename "${1:-iocmon.sh}")"
T="${TMPDIR:-/tmp}/pr-test.$$"; mkdir -p "$T" || exit 1; trap 'rm -rf "$T"' EXIT; rc=0; cd "$T" || exit 1
ok() { echo "PASS $1"; }; no() { echo "FAIL $1"; rc=1; }
check() { if eval "$2"; then ok "$1"; else no "$1"; fi; }

# TERM stops the process and removes its pid file.
{ echo 'pidfile=pid; echo $$ > pid'; grep -F "trap 'rm -f \"\$pidfile\"'" "$S" | head -n 1
  echo 'i=0; while [ "$i" -lt 50 ]; do sleep 1; i=$((i + 1)); done; echo STILL_RUNNING > ran'; } > loop.sh
sh loop.sh & p=$!
n=0; while [ ! -s pid ] && [ "$n" -lt 20 ]; do usleep 100000 2>/dev/null || sleep 1; n=$((n + 1)); done
kill -TERM "$p"; n=0; while kill -0 "$p" 2>/dev/null && [ "$n" -lt 5 ]; do sleep 1; n=$((n + 1)); done
check "TERM stops the process" "! kill -0 $p 2>/dev/null"
kill -9 "$p" 2>/dev/null; wait "$p" 2>/dev/null
check "TERM removes the pid file" "[ ! -e pid ]"

# A stale pid now owned by something else isn't treated as a running monitor.
{ echo 'lock() {'; grep -F '[ "$oldpid" != "$$" ] && ' "$S" | head -n 1; echo 'echo LOCKED; fi; }'; } > own.sh; . ./own.sh
sleep 30 & other=$!
oldpid=$other; check "other process doesn't hold the lock" "[ -z \"\$(lock)\" ]"
kill "$other" 2>/dev/null; wait "$other" 2>/dev/null
printf 'sleep 30\n' > iocmon.sh; sh iocmon.sh & mine=$!
n=0; while ! grep -q iocmon "/proc/$mine/cmdline" 2>/dev/null && [ "$n" -lt 3 ]; do sleep 1; n=$((n + 1)); done
oldpid=$mine; check "a running monitor holds the lock" "[ \"\$(lock)\" = LOCKED ]"
kill "$mine" 2>/dev/null; wait "$mine" 2>/dev/null

# Cron exceptions with quotes and substitutions survive a save and load as text.
cronexceptions='0 4 * * * echo "$(touch PWN)" `touch PWN2` it'"'"'s #x#
5 4 * * * second line'
want=$cronexceptions
grep -F 'cronexceptions=' "$S" | grep -E "^ *(echo|printf)" | head -n 1 > save.sh; . ./save.sh > saved.cfg
cronexceptions=; . ./saved.cfg 2>/dev/null
check "cron exception is not run" "[ ! -e PWN ] && [ ! -e PWN2 ]"
check "cron exception reloads unchanged" "[ \"\$cronexceptions\" = \"\$want\" ]"

exit $rc
