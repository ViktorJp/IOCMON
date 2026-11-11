#!/bin/sh
# Feed indicators in loopback, private and other non-routable ranges must not reach ips.txt or
# qfeeds_ips.txt, which feed both the conntrack watch and the Skynet import.
# Usage: tests/test_nonroutable_indicators.sh [path/to/iocmon.sh]
S="$(cd "$(dirname "${1:-iocmon.sh}")" && pwd)/$(basename "${1:-iocmon.sh}")"
T="${TMPDIR:-/tmp}/pr-test.$$"; mkdir -p "$T/meta" || exit 1; trap 'rm -rf "$T"' EXIT; rc=0; cd "$T" || exit 1
check() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; rc=1; fi; }
fn() { awk -v n="$1()" '$0==n{f=1} f{print} f&&/^}/{exit}' "$S"; }
{ fn dropreservedindicators; fn normalizefeeds; fn fetchqfeedlist; fn dedupindicators; } > f.sh
. ./f.sh
_GetLAN_HostName_() { echo host; }; inlinestatus() { :; }
logfile="$T/log"; feedsroot="$T"; : > "$logfile"
enablefeodo=0; enablespamhaus=0; enablenetapi=0; enableurlhaus=0; enablethreatfox=0; feedsdegraded=0

# Each address is checked alone, so one wrong answer cannot hide behind another.
drops() { printf '%s|src|fam\n' "$1" > one; dropreservedindicators one 2>/dev/null; [ -f one ] && [ ! -s one ]; }
for ip in 127.0.0.1 127.1.2.3 127.000.000.001 0.0.0.0 10.1.2.3 10.0.0.0/8 100.64.0.1 100.127.255.255 169.254.1.1 \
  172.16.0.1 172.31.255.255 192.0.0.1 192.0.2.1 192.168.50.1 192.168.0.0/16 198.18.0.1 198.19.255.255 \
  198.51.100.1 203.0.113.1 224.0.0.1 239.255.255.255 240.0.0.1 255.255.255.255 0.0.0.0/0 8.0.0.0/6 \
  128.0.0.0/2 ::1 ::1/128 :: fe80::1 FE80::1 febf::1 fc00::1 fd00::1 ff02::1; do
  check "drops $ip" "drops '$ip'"
done
for ip in 8.8.8.8 1.2.3.0/24 9.255.255.255 11.0.0.1 100.63.255.255 100.128.0.1 126.255.255.255 128.0.0.1 \
  169.253.255.255 172.15.255.255 172.32.0.1 192.167.255.255 192.169.0.1 198.17.255.255 198.20.0.1 223.255.255.255 \
  1.0.0.0/8 11.0.0.0/8 172.32.0.0/11 192.169.0.0/16 2001:4860:4860::8888 fec0::1 fbff::1; do
  check "keeps $ip" "! drops '$ip' && grep -qF '$ip|src|fam' one"
done

# Lines that aren't IP indicators, or are malformed, aren't this filter's business.
for other in example.com localhost 1.2.3.4/33 not-an-ip; do
	check "leaves alone: $other" "! drops '$other' && grep -qF '$other|src|fam' one"
done

# Lists with no source field, as Q-Feeds has, and empty or missing lists.
printf '127.0.0.1\n8.8.8.8\n' > bare; : > "$logfile"; dropreservedindicators bare 2>/dev/null
check "bare list is filtered" "[ \"\$(cat bare)\" = 8.8.8.8 ]"
check "bare drop is logged without a source" "grep -q 'Dropped 1 .*: 127\\.0\\.0\\.1\\.$' '$logfile'"
: > empty; dropreservedindicators empty 2>/dev/null; rc2=$?
check "empty list is fine" "[ $rc2 = 0 ] && [ -f empty ] && [ ! -s empty ]"
dropreservedindicators missing 2>/dev/null; rc2=$?
check "missing list is fine" "[ $rc2 = 0 ] && [ ! -e missing ]"
check "no temporary file is left" "[ ! -e bare.routable ] && [ ! -e empty.routable ]"

# A long list names the first few, so one bad feed can't flood the log.
i=1; while [ "$i" -le 9 ]; do echo "10.0.0.$i|src|fam"; i=$((i + 1)); done > many; : > "$logfile"; dropreservedindicators many 2>/dev/null
check "large drop gives the full count" "grep -q 'Dropped 9 ' '$logfile'"
check "large drop names only five" "[ \"\$(grep -o '10\\.0\\.0\\.[0-9]' '$logfile' | wc -l | tr -d ' ')\" = 5 ] && grep -q '\\.\\.\\.' '$logfile'"

# Lines that are kept stay byte-identical, and a run with nothing to drop stays quiet.
printf '8.8.8.8|a,b|Fam (x; y)\n1.1.1.1\n' > same; cp same same.orig; : > "$logfile"
dropreservedindicators same 2>/dev/null
check "kept lines unchanged" "cmp -s same same.orig"
check "nothing dropped, nothing logged" "[ ! -s '$logfile' ]"

# What was dropped is logged, with its source, so a filtered feed entry is never silent.
printf '127.0.0.1|threatfox|Mirai\n8.8.8.8|x|y\n' > one; dropreservedindicators one 2>/dev/null
check "drop is logged with its source" "grep -q 'Dropped 1 .*127\.0\.0\.1 (threatfox)' '$logfile'"

# The record that started this: a ThreatFox URL IOC of http://127.0.0.1, through the real normalizer.
threatfoxtsv() { printf 'http://127.0.0.1\turl\tMirai\t75\tbotnet_cc\thoneypot\nhttp://8.8.4.4/x\turl\tMirai\t75\tbotnet_cc\t\n'; }
enablethreatfox=1; echo api > meta/threatfox.mode; echo raw > threatfox.raw; rm -f ips.txt
printf '192.168.50.1\n8.8.8.8\n' > feodo.raw; enablefeodo=1
normalizefeeds >/dev/null 2>&1
check "normalizer drops the ThreatFox loopback record" "[ -f ips.txt ] && ! grep -q '^127\.' ips.txt"
check "normalizer drops a private address from another feed" "[ -f ips.txt ] && ! grep -q '^192\.168\.' ips.txt"
check "normalizer keeps public addresses" "grep -q '^8\.8\.4\.4|' ips.txt && grep -q '^8\.8\.8\.8|' ips.txt"

# Q-Feeds has its own download path, and its list is imported to Skynet as well.
curl() { while [ $# -gt 0 ]; do [ "$1" = "-o" ] && { { echo 127.0.0.1; echo 10.0.0.0/8; i=1; while [ "$i" -le 1100 ]; do echo "8.8.$((i / 250)).$((i % 250))"; i=$((i + 1)); done; } > "$2"; }; shift; done; printf 200; }
qfeedsapikey=x; rm -f qf.txt
fetchqfeedlist malware_ip "$T/qf.txt" ip >/dev/null 2>&1
check "Q-Feeds list is written" "[ -s qf.txt ]"
check "Q-Feeds list drops non-routable addresses" "[ -s qf.txt ] && ! grep -qE '^(127|10)\.' qf.txt"
check "Q-Feeds list keeps public addresses" "[ \"\$(wc -l < qf.txt 2>/dev/null | tr -d ' ')\" = 1100 ]"
exit $rc
