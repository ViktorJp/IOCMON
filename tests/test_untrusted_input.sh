#!/bin/sh
# Runs the DNS, feed, download and email code from iocmon.sh on hostile input.
# Usage: tests/test_untrusted_input.sh [path/to/iocmon.sh]
S="$(cd "$(dirname "${1:-iocmon.sh}")" && pwd)/$(basename "${1:-iocmon.sh}")"
T="${TMPDIR:-/tmp}/pr-test.$$"; mkdir -p "$T" || exit 1; trap 'rm -rf "$T"' EXIT; rc=0; cd "$T" || exit 1
ok() { echo "PASS $1"; }; no() { echo "FAIL $1"; rc=1; }
check() { if eval "$2"; then ok "$1"; else no "$1"; fi; }
fn() { awk -v n="$1()" '$0==n{f=1} f{print} f&&/^}/{exit}' "$S"; }
_GetLAN_HostName_() { echo host; }; sleep() { :; }; logfile=run.log

# Hostile DNS log lines.
sed -n "/grep -F 'dnsmasq' | awk '\$/,/^ *' | sort -u)\"/p" "$S" | sed '1d;$d' > p.awk
cat > dns.log <<'L'
Nov  8 04:00:00 dnsmasq[1]: query[A] evil.com|a->$(touch${IFS}/tmp/pwn) from 192.168.50.13
Nov  8 04:00:01 dnsmasq[1]: query[A] evil.com|192.168.50.66 from 192.168.50.13
Nov  8 04:00:02 dnsmasq[1]: forwarded x query[A] evil.com from 6.6.6.6 to 127.0.1.1
Nov  8 04:00:03 dnsmasq[1]: query[A] EVIL.COM from 192.168.50.13
Nov  8 04:00:06 dnsmasq[1]: query[AAAA] good.example.com from 2600:4041::1
L
awk -f p.awk dns.log > dns.out 2>&1
check "shell metacharacters stripped" "! grep -q '[\$(){}]' dns.out"
check "one separator per pair" "[ \"\$(awk -F'|' 'NF!=2' dns.out | wc -l | tr -d ' ')\" = 0 ]"
check "spoofed source ignored" "! grep -q '6\.6\.6\.6' dns.out"
check "domain lower-cased, real source kept" "grep -q '^evil\.com|192\.168\.50\.13$' dns.out"
check "normal IPv6 query kept" "grep -q '^good\.example\.com|2600:4041::1$' dns.out"

# A feed serving an error page adds nothing.
mkdir feeds; feedsroot=feeds; tmpips=ips.out
printf '<html>error</html>\n1.2.3.4\n5.6.7.0/24\n' > feeds/feodo.raw
grep -F 'print $1"|feodo|botnet-c2"' "$S" | head -n 1 > feed.sh; . ./feed.sh
check "feed keeps valid addresses" "grep -q '^1.2.3.4|' ips.out && grep -q '^5.6.7.0/24|' ips.out"
check "feed drops other lines" "! grep -q html ips.out"

# curl stub: records its arguments and saves the body in $CURL_BODY to the -o file.
curl() {
	printf '%s\n' "$*" >> curl.args
	while [ $# -gt 0 ]; do [ "$1" = -o ] && printf '%s\n' "$CURL_BODY" > "$2"; shift; done
	return 0
}

# The email library is fetched with TLS checks, and a broken download keeps the installed copy.
eval "$(fn _DownloadCEMLibraryFile_)"
mkdir lib; CUSTOM_EMAIL_LIBDir=lib; CUSTOM_EMAIL_LIBName=lib.sh; CUSTOM_EMAIL_LIBFile=lib/lib.sh; CEM_LIB_URL=https://example.invalid
echo 'good=1' > lib/lib.sh; CURL_BODY='if ('
( _DownloadCEMLibraryFile_ install ) > /dev/null 2>&1
check "email library verifies TLS" "grep -q . curl.args && ! grep -qE '(^| )-[a-zA-Z]*k' curl.args"
check "broken email library not installed" "grep -q good=1 lib/lib.sh"

# A broken script update keeps the installed script.
eval "$(fn ondiskversion)"; eval "$(fn scriptfilevalid)"; eval "$(fn downloadiocmonupdate)"
apppath=app.sh; printf 'version="1.0"\necho installed\n' > app.sh; iocmonreposcriptstable=https://example.invalid
CURL_BODY='if ('; ( downloadiocmonupdate https://example.invalid/x STABLE ) > /dev/null 2>&1
check "broken update not installed" "grep -q 'echo installed' app.sh"
CURL_BODY='version="2.0"'; ( downloadiocmonupdate https://example.invalid/x STABLE ) > /dev/null 2>&1
check "valid update installed" "grep -q 'version=\"2.0\"' app.sh"

# Logged text is data, not a printf format.
statustext='50%s done'
grep -F 'Email notification was sent successfully' "$S" | grep '^ *printf' | head -n 1 > status.sh
. ./status.sh > status.out 2>&1
check "status not used as printf format" "grep -qF '50%s done' status.out"

sh -n "$S" && ok syntax || no syntax
exit $rc
