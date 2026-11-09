#!/bin/sh
# Runs the login checks from iocmon.sh on the lines the firmware's httpd and dropbear write.
# Usage: tests/test_failed_login_detection.sh [path/to/iocmon.sh]
S="$(cd "$(dirname "${1:-iocmon.sh}")" && pwd)/$(basename "${1:-iocmon.sh}")"
T="${TMPDIR:-/tmp}/pr-test.$$"; mkdir -p "$T" || exit 1; trap 'rm -rf "$T"' EXIT; rc=0; cd "$T" || exit 1
check() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; rc=1; fi; }

for v in dropbearlines httpdlines dropbearips httpdips; do grep -F "$v=\"\$(" "$S" | head -n 1; done > auth.sh
synclog=log; authnewlines() { cat; }; dropbearseenfile=x; httpdseenfile=x
scan() { . ./auth.sh; }
web() { printf '%s\n' "$httpdips" | grep -c "^$1$"; }
ssh() { printf '%s\n' "$dropbearips" | grep -c "^$1$"; }

# Strings from web.c ("[LOGIN][%s][%s] failed (%s)") and dropbear's svr-auth code.
cat > log <<'L'
Nov  9 03:00:00 HTTPD: [LOGIN][https][Web] failed (203.0.113.1)
Nov  9 03:00:01 HTTPD: [LOGIN][http][Web] failed (203.0.113.2)
Nov  9 03:00:02 HTTPD: [LOGIN][https][APP] failed (203.0.113.3)
Nov  9 03:00:03 HTTPD[412]: [LOGIN][https][Web] failed (203.0.113.4)
Nov  9 03:00:04 HTTPD: [LOGIN][https][Web] failed (203.0.113.1)
Nov  9 03:00:05 HTTPD: [LOGIN][https][Web] successful (198.51.100.1)
Nov  9 03:00:06 HTTPD: [LOGIN][https][Web] captcha error (198.51.100.2)
Nov  9 03:00:07 dnsmasq[1]: query[A] httpd.login.fail.example from 198.51.100.3
Nov  9 03:00:08 miniupnpd[9]: HTTPD: [LOGIN] text failed (198.51.100.4)
Nov  9 03:00:10 dropbear[12]: Bad password attempt for 'admin' from 203.0.113.5:40000
Nov  9 03:00:11 dropbear[12]: Login attempt for nonexistent user from 203.0.113.6:40001
Nov  9 03:00:12 dropbear[12]: Login attempt for nonexistent user from 203.0.113.6:40002
Nov  9 03:00:13 dropbear[12]: Password auth succeeded for 'admin' from 198.51.100.5:40003
Nov  9 03:00:14 dropbear[12]: Pubkey auth succeeded for 'admin' with key from 198.51.100.6:40004
Nov  9 03:00:15 dropbear[12]: Child connection from 198.51.100.7:40005
L
scan

check "failed https web login is counted" "[ \"\$(web 203.0.113.1)\" = 2 ]"
check "failed http web login is counted" "[ \"\$(web 203.0.113.2)\" = 1 ]"
check "failed app login is counted" "[ \"\$(web 203.0.113.3)\" = 1 ]"
check "failed login with a tagged pid is counted" "[ \"\$(web 203.0.113.4)\" = 1 ]"
check "successful web login isn't counted" "[ \"\$(web 198.51.100.1)\" = 0 ]"
check "captcha error isn't counted" "[ \"\$(web 198.51.100.2)\" = 0 ]"
check "DNS query can't fake a web login" "[ \"\$(web 198.51.100.3)\" = 0 ]"
check "other programs can't fake a web login" "[ \"\$(web 198.51.100.4)\" = 0 ]"

check "wrong SSH password is counted" "[ \"\$(ssh 203.0.113.5)\" = 1 ]"
check "each SSH try for an unknown user is counted" "[ \"\$(ssh 203.0.113.6)\" = 2 ]"
check "good SSH password isn't counted" "[ \"\$(ssh 198.51.100.5)\" = 0 ]"
check "good SSH key isn't counted" "[ \"\$(ssh 198.51.100.6)\" = 0 ]"
check "plain SSH connection isn't counted" "[ \"\$(ssh 198.51.100.7)\" = 0 ]"

: > log; scan
check "quiet log counts nothing" "[ -z \"\$httpdips\" ] && [ -z \"\$dropbearips\" ]"
exit $rc
