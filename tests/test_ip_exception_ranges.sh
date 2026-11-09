#!/bin/sh
# An IP exception must reach the Skynet import even when a feed bans a range containing it.
# Usage: tests/test_ip_exception_ranges.sh [path/to/iocmon.sh]
S="$(cd "$(dirname "${1:-iocmon.sh}")" && pwd)/$(basename "${1:-iocmon.sh}")"
T="${TMPDIR:-/tmp}/pr-test.$$"; mkdir -p "$T" || exit 1; trap 'rm -rf "$T"' EXIT; rc=0; cd "$T" || exit 1
check() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; rc=1; fi; }
awk '$0=="buildskynetimportfile()"{f=1} f{print} f&&/^}/{exit}' "$S" > f.sh; . ./f.sh
skynetprogress() { :; }; feedsroot=.; skynetimportqfeeds=0

build() { ipexceptions="$1"; shift; : > ips.txt; for e in "$@"; do echo "$e|src|fam" >> ips.txt; done; buildskynetimportfile out; }

# Lists every address the output covers, one per line, so a split is judged by what it bans.
addresses() {
  awk -F/ '{ split($1, o, "."); v = o[1]*16777216 + o[2]*65536 + o[3]*256 + o[4]; n = 2 ^ (32 - ($2 == "" ? 32 : $2))
    for (i = 0; i < n; i++) { a = v + i; print int(a/16777216) "." (int(a/65536) % 256) "." (int(a/256) % 256) "." (a % 256) } }' "$1" | sort
}
# Bans exactly $3 and nothing else: 1.2.3.N for each N listed.
want() { for n in $1; do echo "1.2.3.$n"; done | sort > want.txt; }
others_of() { i=0; while [ "$i" -lt 256 ]; do case " $1 " in *" $i "*) ;; *) printf '%s ' "$i" ;; esac; i=$((i + 1)); done; }
bans_all_but() { want "$(others_of "$1")"; addresses out > got.txt; cmp -s got.txt want.txt; }

build "1.2.3.4" 1.2.3.0/24
check "exception inside a range is no longer banned" "! addresses out | grep -qx 1.2.3.4"
check "the rest of the range stays banned" "bans_all_but 4"
check "the split uses as few entries as it can" "[ \"\$(wc -l < out | tr -d ' ')\" = 8 ]"

build "1.2.3.0" 1.2.3.0/24; check "first address of a range" "bans_all_but 0"
build "1.2.3.255" 1.2.3.0/24; check "last address of a range" "bans_all_but 255"
build "1.2.3.4/32" 1.2.3.0/24; check "single address written as /32" "bans_all_but 4"
build "1.2.3.4 1.2.3.200" 1.2.3.0/24; check "two exceptions in one range" "bans_all_but '4 200'"
build "1.2.3.4 1.2.3.4" 1.2.3.0/24; check "repeated exception" "bans_all_but 4"
build "1.2.3.0/30" 1.2.3.0/24; check "smaller range as the exception" "bans_all_but '0 1 2 3'"
build "1.2.3.0/30 1.2.3.2" 1.2.3.0/24; check "overlapping exceptions" "bans_all_but '0 1 2 3'"
build "1.2.3.128/25" 1.2.3.0/24; check "half a range leaves the other half" "[ \"\$(cat out)\" = 1.2.3.0/25 ]"

build "1.2.3.0/24" 1.2.3.0/24; check "exception equal to the range removes it" "[ ! -s out ]"
build "1.2.0.0/16" 1.2.3.0/24; check "exception wider than the range removes it" "[ ! -s out ]"
build "0.0.0.0/0" 1.2.3.0/24 8.8.8.8; check "exception for everything removes all" "[ ! -s out ]"
build "1.2.3.4" 1.2.3.4; check "exception equal to a single address removes it" "[ ! -s out ]"

build "9.9.9.9" 1.2.3.0/24 8.8.8.8; check "unrelated exception changes nothing" "[ \"\$(sort out | tr '\n' ' ')\" = '1.2.3.0/24 8.8.8.8 ' ]"
build "1.2.4.0" 1.2.3.0/24; check "address just past a range changes nothing" "[ \"\$(cat out)\" = 1.2.3.0/24 ]"
build "1.2.3.4/33" 1.2.3.0/24; check "exception with a bad mask is ignored" "[ \"\$(cat out)\" = 1.2.3.0/24 ]"
build "" 1.2.3.0/24 8.8.8.8; check "no exceptions leaves the list alone" "[ \"\$(sort out | tr '\n' ' ')\" = '1.2.3.0/24 8.8.8.8 ' ]"

# A wide range stays cheap: one address out of a /8 takes 24 entries.
build "10.1.2.3" 10.0.0.0/8; check "wide range splits into one entry per bit" "[ \"\$(wc -l < out | tr -d ' ')\" = 24 ] && ! grep -qx 10.1.2.3 out"

# Q-Feeds entries are filtered the same way.
echo '5.5.5.0/30' > qfeeds_ips.txt; skynetimportqfeeds=1
build "5.5.5.1" 1.2.3.4; check "Q-Feeds ranges are split too" "[ \"\$(sort out | tr '\n' ' ')\" = '1.2.3.4 5.5.5.0 5.5.5.2/31 ' ]"
exit $rc
