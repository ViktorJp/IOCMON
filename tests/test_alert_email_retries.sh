#!/bin/sh
# A failed alert email must not lose the alert. The mailer is a stub, so nothing is sent.
# Usage: tests/test_alert_email_retries.sh [path/to/iocmon.sh]
S="$(cd "$(dirname "${1:-iocmon.sh}")" && pwd)/$(basename "${1:-iocmon.sh}")"
T="${TMPDIR:-/tmp}/pr-test.$$"; mkdir -p "$T/state" || exit 1; trap 'rm -rf "$T"' EXIT; rc=0; cd "$T" || exit 1
ext() { awk -v n="$1" '$0==n"()"{f=1} f{print} f&&/^}/{exit}' "$S"; }
for f in emailrow emaillinkrow emaildivider emailsection emailfamilyrows emailfeedname isfeedmatchsource abusechemaillinks emailalertbody ratelimiter sendmessage sendbatchmessage queueemailalert flushemailbatch _SendEMailNotification_; do ext "$f"; done > f.sh
grep -m1 '^emailfallbacksubject=' "$S" >> f.sh
. ./f.sh
sleep() { :; }; loadcemlibrary() { :; }; resolvestateroot() { :; }; _GetLAN_HostName_() { echo r; }
amtmIsEMailConfigFileEnabled=1; enablealertemail=1; ratelimit=0; version=t; emailwrapwidth=78; scriptFileNTag=t
addonsdir="$T"; logfile="$T/log"; stateroot="$T/state"; mkdir -p /tmp/var/tmp
P="$stateroot/email_batch.pending"; R="$stateroot/email_batch.retry"; M="$T/mail"

# MODE=ok delivers, MODE=down always fails, MODE=reject fails when the message contains $FLAG.
_SendEMailNotification_CEM_() {
  b="${2#-F=}"; { printf 'SUBJ %s\n' "$1"; cat "$b"; echo "=END"; } >> "$M"
  case "$MODE" in
    down) return 7 ;;
    reject) { printf '%s\n' "$1"; cat "$b"; } | grep -qF "$FLAG" && return 55 ;;
  esac
  return 0
}
new() { MODE="$1"; FLAG="$2"; rm -f "$P" "$R" "$stateroot"/email_batch.*; : > "$M"; : > "$logfile"; }
sends() { grep -c '^SUBJ' "$M"; }
alert() { queueemailalert conntrack "192.168.50.2->$1" urlhaus d - ''; }
flush() { flushemailbatch >/dev/null 2>&1; }
check() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; rc=1; fi; }

# A delivered alert leaves nothing behind.
new ok ''; alert 9.9.9.1; flush
check "delivered alert sends one email" '[ "$(sends)" = 1 ]'
check "delivered alert clears the batch" '[ ! -s "$P" ] && [ ! -e "$R" ] && [ ! -e "$stateroot/email_batch.sending" ]'

# An outage holds the alert and tries again later.
new down ''; alert 9.9.9.2; flush
check "outage keeps the alert" 'grep -qF 9.9.9.2 "$P"'
check "outage counts the attempt" '[ "$(cut -d" " -f1 "$R")" = 1 ]'
check "outage sets a retry time about 10 minutes out" '[ "$(cut -d" " -f2 "$R")" -gt "$(($(date +%s) + 500))" ] && [ "$(cut -d" " -f2 "$R")" -le "$(($(date +%s) + 600))" ]'
check "outage logs the failure" 'grep -qF "Failure to send" "$logfile"'
: > "$M"; flush
check "nothing is sent during the wait" '[ "$(sends)" = 0 ] && grep -qF 9.9.9.2 "$P"'

# An alert raised during the wait goes out with the held one.
alert 9.9.9.3; MODE=ok; echo "1 0" > "$R"; flush
check "held and new alerts both go out" 'grep -qF 9.9.9.2 "$M" && grep -qF 9.9.9.3 "$M"'
check "recovery clears the batch and the wait" '[ ! -s "$P" ] && [ ! -e "$R" ]'

# A long outage has an end, and says so.
new down ''; alert 9.9.9.4; echo "4 0" > "$R"; flush
check "fifth attempt still keeps the alert" 'grep -qF 9.9.9.4 "$P" && [ "$(cut -d" " -f1 "$R")" = 5 ]'
echo "5 0" > "$R"; flush
check "sixth attempt stops retrying" '[ ! -s "$P" ] && [ ! -e "$R" ]'
check "stopping is logged" 'grep -qF "Gave up emailing" "$logfile"'

# A damaged retry file doesn't block delivery.
for bad in 'x y' '' '-1 -1' '$(touch PWN) 0'; do
  new ok ''; alert 9.9.9.5; printf '%s\n' "$bad" > "$R"; flush
  check "damaged retry file is ignored: $bad" '[ "$(sends)" = 1 ] && [ ! -e "$R" ] && [ ! -e PWN ]'
done

# A held batch can't grow without limit.
new down ''; i=0; while [ "$i" -lt 120 ]; do alert "10.0.0.$i"; i=$((i + 1)); done; flush
check "held batch is capped at 100 lines" '[ "$(wc -l < "$P" | tr -d " ")" -le 100 ]'
check "the cap keeps the newest alerts" 'grep -qF 10.0.0.119 "$P"'

# A message the provider rejects gets a notice instead, which can't be rejected for the same reason.
new reject SECRETFLAG; queueemailalert dns '192.168.50.2->x.example' netapi 'family SECRETFLAG' - ''; flush
check "rejected alert sends a notice" '[ "$(sends)" = 2 ]'
check "notice has no indicators" '! sed -n "/^=END/,\$p" "$M" | grep -qE "x\.example|SECRETFLAG"'
check "notice names the log" 'sed -n "/^=END/,\$p" "$M" | grep -qF "$logfile"'
check "delivered notice ends the retries" '[ ! -s "$P" ] && [ ! -e "$R" ]'

# When the notice fails too, it stops there and the alert is held.
new down ''; alert 9.9.9.6; flush
check "failed notice isn't retried in a loop" '[ "$(sends)" = 2 ]'
check "failed notice holds the alert" 'grep -qF 9.9.9.6 "$P"'

# Test emails report their failure directly.
new down ''; sendmessage 1 test "Test alert" manual x >/dev/null 2>&1
check "failed test email sends no notice" '[ "$(sends)" = 1 ]'

# Being unable to send at all isn't a sent email.
unset -f _SendEMailNotification_CEM_; _DownloadCEMLibraryFile_() { :; }
amtmIsEMailConfigFileEnabled=; CUSTOM_EMAIL_LIBFile=./missing; emailsendrc=0
_SendEMailNotification_ a b c > /dev/null 2>&1
check "missing email library isn't a sent email" '[ "$emailsendrc" != 0 ]'
CUSTOM_EMAIL_LIBFile=./present; : > present; emailsendrc=0
_SendEMailNotification_ a > /dev/null 2>&1
check "missing email parameters aren't a sent email" '[ "$emailsendrc" != 0 ]'
exit $rc
