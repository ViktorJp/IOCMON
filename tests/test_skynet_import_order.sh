#!/bin/sh
# syncskynetimport must import before removing the old rule, and keep it if the import fails.
# Usage: tests/test_skynet_import_order.sh [path/to/iocmon.sh]
S="${1:-iocmon.sh}"; T="${TMPDIR:-/tmp}/pr-test.$$"; mkdir -p "$T" || exit 1; trap 'rm -rf "$T"' EXIT; rc=0; mkdir "$T/meta"
ext() { awk -v n="$1" '$0==n"()"{f=1} f{print} f&&/^}/{exit}' "$S"; }
{ ext skynetimportids; ext removeskynetimports; ext syncskynetimport; } | sed "s#sh /jffs/scripts/firewall#sh $T/fw#g" > "$T/f.sh"
cat > "$T/fw" <<F
R=$T/skynet.rules; echo "\$1 \$2" >> $T/calls
case "\$1 \$2" in
 "rules remove") grep -v "^R2	\$3	" \$R > \$R.n; mv \$R.n \$R ;;
 "import blacklist") [ -n "\$FAILIMPORT" ] && exit 1; [ -n "\$NOOPIMPORT" ] && exit 0; printf 'R2\tnew\tban\timport\tv\tCIOCMON n\tenabled\t0\t0\td\n' >> \$R ;;
esac
exit 0
F
cat > "$T/run" <<F
. $T/f.sh
enableskynetimport=1; skynetmissinglogged=0; feedsroot=$T; logfile=$T/log; skynetimportqfeeds=0; ipexceptions=; skynetstoragepath=$T
resolveskynetloc(){ :; }; skynetprogress(){ :; }; skynetinstalled(){ return 0; }; nvram(){ echo r; }; _GetLAN_HostName_(){ echo r; }
buildskynetimportfile(){ printf '%b' "\$ENTRIES" > "\$1"; }; filecontenthash(){ cksum < "\$1"; }
syncskynetimport force
F
t() { n="$1"; want_calls="$2"; want_rules="$3"; shift 3; : > "$T/calls"
  printf 'R2\told\tban\timport\tv\tCIOCMON a\tenabled\t0\t0\td\nR2\tkeep\tban\tip\tv\tCmine\tenabled\t0\t0\td\n' > "$T/skynet.rules"
  env ENTRIES='1.2.3.4\n' "$@" sh "$T/run" >/dev/null 2>&1
  c="$(tr '\n' ';' < "$T/calls")"; r="$(cut -f2 "$T/skynet.rules" | sort | tr '\n' ' ')"
  if [ "$c" = "$want_calls" ] && [ "$r" = "$want_rules" ]; then echo "PASS $n"; else echo "FAIL $n: calls[$c] rules[$r]"; rc=1; fi; }
t "normal: import, then remove old" "import blacklist;rules remove;" "keep new " A=1
t "failed import keeps old rule" "import blacklist;import blacklist;import blacklist;" "keep old " FAILIMPORT=1
t "import adding nothing keeps old rule" "import blacklist;" "keep old " NOOPIMPORT=1
t "empty feed removes old rule" "rules remove;" "keep " ENTRIES=
exit $rc
