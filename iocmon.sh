#!/bin/sh
# ============================================================================================================================
# iocmon.sh - Asus-Merlin Firmware Security-Intelligence Monitor
# Version: 2.0.6
# Sibling to BACKUPMON, STUNMON, TAILMON, VPNMON-R3, RTRMON, KILLMON, ECLIPSEMON, WXMON and PWRMON
# Last Updated: 2026-Nov-10
# ============================================================================================================================
#
# Description:
#   Reads syslog and other router-provided logs, watches for filesystem changes, and correlates against public
#   indicator-of-compromise (IoC) feeds to alert the user of possible compromise or malware on the router.
#
# File layout:
#   /jffs/scripts/iocmon.sh                                             : main script - control plane, survives reboot
#   /jffs/addons/iocmon.d/iocmon.cfg                                    : config (flat key=value, sourced)
#   /jffs/addons/iocmon.d/version.txt                                   : stable track version file
#   /jffs/addons/iocmon.d/beta.txt                                      : beta track version file
#   /jffs/addons/iocmon.d/iocmon.log                                    : activity/alert log (nano-viewable, rotated to .1/.2 at $logsize lines) - default location
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/iocmon.log                  : optional drive-side activity log location (logfilepath), to spare JFFS writes
#   /jffs/addons/iocmon.d/updating.txt                                  : maintenance-mode lock file
#   /jffs/addons/iocmon.d/iocmon.asp                                    : router web interface page, copied to a /www/user slot when the toggle is on
#   /www/ext/iocmon/                                                    : web interface data files (RAM, HTML-escaped, rebuilt each boot)
#   /jffs/addons/shared-jy/redirect.htm                                 : shared Help & Support target, only if no other add-on supplied one
#   /jffs/addons/iocmon.d/feeds-degraded/                               : small JFFS-safe feed cache used only in degraded mode
#   /jffs/addons/iocmon.d/state-degraded/                               : small JFFS-safe alert-dedup state used only in degraded mode
#   /tmp/mnt/<extdrivelabel>/iocmon.d/feeds/ips.txt                     : canonical combined IP/netblock indicator list
#   /tmp/mnt/<extdrivelabel>/iocmon.d/feeds/domains.txt                 : canonical combined domain indicator list
#   /tmp/mnt/<extdrivelabel>/iocmon.d/feeds/qfeeds_ips.txt/_domains.txt : Q-Feeds bare indicator lists (matched by streaming)
#   /tmp/mnt/<extdrivelabel>/iocmon.d/feeds/hashes.txt                  : canonical combined file-hash indicator list
#   /tmp/mnt/<extdrivelabel>/iocmon.d/feeds/*.raw                       : per-source raw downloads (urlhaus.raw = abuse.ch CSV export, urlhaus_payloads.raw = payload JSON, netapi_ips.raw/netapi_domains.raw = NetAPI lists)
#   /tmp/mnt/<extdrivelabel>/iocmon.d/feeds/meta/                       : per-source conditional-GET timestamp markers
#   /tmp/mnt/<extdrivelabel>/iocmon.d/feeds/meta/skynet_import.hash     : last-imported Skynet IP list hash, so an unchanged list skips the re-push
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/seen_alerts.db              : "kind|indicator<TAB>epoch" alert dedup records
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/dns_checkpoint              : syslog line-count cursor for checkdns (+ dns_anchor, its last-line anchor)
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/agh_cursor                  : newest AdGuard Home query-log entry already checked (AdGuard Home DNS source)
#   /tmp/iocmon_agh_replies                                             : recent AdGuard Home "domain|ip" answers for the reputation lookup (RAM only)
#   /tmp/astraea/selfq, /tmp/kairos/selfq                               : read only - the router's own lookups for Astraea/Kairos, set aside by DNS watch
#   /tmp/kairos/status                                                  : read only - Kairos's state; its selfq is used only while this was written in the last 3 minutes
#   /tmp/iocmon_selfq_seen, /tmp/iocmon_astraea_intel                   : set-aside lookups already logged, and recent Astraea verdicts for emails (RAM)
#   /jffs/addons/iocmon.d/dropbear_seen.db, httpd_seen.db               : content ledgers of auth-failure lines already counted (checkauth) - kept on JFFS, not the drive, so a drive flap can't cause a replay
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/dropbear_attempts.log       : dropbear auth-failure log, syslog lines with the year added, rotated to .1/.2 at $logsize lines
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/fs_baseline.db              : plain sorted file-path list (no stat - see below)
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/fs_scan_marker              : reference file `find -newer` compares against
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/cron_baseline.db            : last-seen `cru l` output for the cron-diff heuristic
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/fs_last_check               : epoch stamp gating the fsintegrityhrs cadence
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/fs_scan_summary.txt         : human-readable last-scan detail (main screen)
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/fs_scan_errors.txt          : this cycle's find stderr, if any
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/fs_size_baseline.db         : per-file size, for mtime-independent MOD detection
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/fs_content_hash.db          : per-file content hash, used only when fsmodalertmode=hash
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/fs_last_new.txt             : timestamped log of added filenames, rotated to .1/.2 at $logsize lines
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/fs_last_modified.txt        : timestamped log of modified filenames
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/fs_last_deleted.txt         : timestamped log of deleted filenames
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/fs_last_permchanged.txt     : timestamped log of permission-only changes
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/ioc_alerts.log              : every real detection ever made, rotated to .1/.2 at $logsize lines
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/alert_pending               : pending-count + latest summary; presence = red banner up
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/hash_check.log              : every NEW/MOD file checked against feeds/hashes.txt, rotated to .1/.2 at $logsize lines
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/reputation.log              : every AbuseIPDB reputation lookup (or skip reason) for a raised alert, rotated to .1/.2 at $logsize lines
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/abuseipdb_cache.db          : "ip|epoch|score|..." AbuseIPDB results reused for abuseipdbcachehrs (+ abuseipdb_usage/_block quota state)
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/etc_critical_hash.db        : per-file content hash baseline for $etccriticalpaths - see checketccritical()
#
# Usage:
#   iocmon.sh                                                           : interactive monitoring display
#   iocmon.sh -setup                                                    : configuration menu (drive/feeds/DNS/advanced settings, uninstall)
#   iocmon.sh -screen [-now]                                            : run the monitoring loop in a background SCREEN session
#   iocmon.sh -email                                                    : send a test email to confirm AMTM notifications are configured
#   iocmon.sh -updatefeeds                                              : cron-callable one-shot IoC feed refresh
#   iocmon.sh -fsintegrity                                              : cron-callable one-shot filesystem-integrity + cron-baseline check
#   iocmon.sh -webmount                                                 : services-start boot hook that rebuilds the web interface tab
#   iocmon.sh -webaction <name>                                         : service-event hook that runs a web interface button's job
#   iocmon.sh -h | -help                                                : this output
#
# Main-screen hotkeys (in addition to (c)onfig/(f)eeds/(i)ntegrity/(l)ogs/(e)xit):
#   (v) view the full log behind whichever "Recent..." panel is showing   (t) simulate a detection from a real,
#   (a) acknowledge the persistent red alert banner                            currently loaded feed indicator
#   (d)/(o)/(h)/(u) switch the "Recent..." panel to Dropbear/IoC Detections/Hash-Check/Reputation
#   (r) clear whichever log the "Recent..." panel is currently showing (confirmation required)
#   (z) add a numbered "dns" entry's base domain (IoC Detections panel only) to the DNS Exceptions list
#   (n) show a last-7-days, date-sorted OTX AlienVault Threat Report (IoC Detections panel only)
#   (p) pause/resume the countdown timer without triggering a rescan
#   (x) detach from the background SCREEN session without stopping IOCMON
#
# ============================================================================================================================

export PATH="/sbin:/bin:/usr/sbin:/usr/bin:$PATH"
unset LD_LIBRARY_PATH

# Resolves to Entware's GNU find if present, since the PATH order above can shadow it with a more limited BusyBox find applet.
if [ -x /opt/bin/find ]; then
  findbin="/opt/bin/find"
else
  findbin="find"
fi

# Probes whether $findbin supports GNU -printf, so file sizes can be batched (one find call per directory) instead of forked per file.
if "$findbin" "$findbin" -maxdepth 0 -printf '' >/dev/null 2>&1; then
  findsupportsprintf=1
else
  findsupportsprintf=0
fi

# HOME/SCREENDIR fix added by Martinski W. [2026-Apr-13]
[ "$HOME" != "/root" ] && export HOME="/root"
export SCREENDIR="${HOME}/.screen"

# To support automatic script updates from AMTM #
doScriptUpdateFromAMTM=true

# -------------------------------------------------------------------------------------------------------------------------
# Static Variables - please do not change
version="2.0.6"
apppath="/jffs/scripts/iocmon.sh"  # this script's own deployed path
addonsdir="/jffs/addons/iocmon.d"  # JFFS-side control/config directory
config="/jffs/addons/iocmon.d/iocmon.cfg"  # persisted key=value config file
dlverpath="/jffs/addons/iocmon.d/version.txt"  # stable-track version file
bverpath="/jffs/addons/iocmon.d/beta.txt"  # beta-track version file
jffslogfile="/jffs/addons/iocmon.d/iocmon.log"  # default (JFFS) activity log location
logfile="$jffslogfile"  # main activity/alert log actually written to - resolved from logfilepath by resolvelogfile()
updatingfile="/jffs/addons/iocmon.d/updating.txt"  # maintenance-mode lock file
restartpendingfile="/jffs/addons/iocmon.d/restart_pending"  # presence = -autoupdate/AMTM downloaded a newer version; the persistent loop restarts into it next cycle
dropbearseenfile="/jffs/addons/iocmon.d/dropbear_seen.db"  # ledger of dropbear failure lines already logged/counted - stays on JFFS deliberately
httpdseenfile="/jffs/addons/iocmon.d/httpd_seen.db"  # ledger of httpd auth-failure lines already counted
webuiversion="1.4.1"  # web interface page version this script expects
webuirecentdays=14  # days of each log published for the page's normal view
webuirecentrows=2000  # most rows of each log published for the normal view
webuifullrows=20000  # most rows loaded by Full History
webuifullkeep=1800  # seconds a Full History copy stays in RAM
webuicheckage=21600  # seconds before the page's automatic update check runs again
webuipagefile="/jffs/addons/iocmon.d/iocmon.asp"  # persistent copy of the web interface page
webuidir="/www/ext/iocmon"  # web interface data files, in RAM
webuiuserdir="/www/user"  # firmware add-on page slots
webuimenutree="/www/require/modules/menuTree.js"  # firmware menu file the edited copy is bound over
webuimenutmp="/tmp/menuTree.js"  # menu copy shared by all add-ons
webuimenubak="/tmp/menuTree.js.iocmon"  # our restore point while editing the shared menu
webuilockfile="/tmp/addonwebui.lock"  # lock shared by add-ons editing the menu
webuisharedjffs="/jffs/addons/shared-jy"  # folder add-ons share for common web files, kept on JFFS
webuisharedweb="/www/ext/shared-jy"  # web path add-ons expect as a link to webuisharedjffs
webuiredirect="$webuisharedjffs/redirect.htm"  # target of the shared Help & Support tab
webuiredirectmark="IOCMON-WEBUI-REDIRECT"  # marks a redirect.htm that IOCMON wrote
webuiservicesstart="/jffs/scripts/services-start"  # boot hook file
webuiserviceevent="/jffs/scripts/service-event"  # hook file the page's buttons reach IOCMON through
webuijoblock="/tmp/iocmon_webjob.lock"  # held while a web job runs, so only one runs at a time
feedslockfile="/tmp/iocmon_feeds.lock"  # held during a feed refresh, in RAM so a reboot can't leave it stale
webuitab="IOCMON"  # tab name in the Addons menu
webuitag="# iocmon-webui"  # tag on our boot hook line
webuimarker="<!-- IOCMON-WebUI"  # identifies our page in a slot and in a download
dnslogknownpaths="/opt/var/log/dnsmasq.log /var/log/dnsmasq.log /tmp/dnsmasq.log"  # dnsmasq-only log files tried when auto-detecting the DNS query log

# Repo used for self-update checks.
iocmonrepostable="https://raw.githubusercontent.com/ViktorJp/IOCMON/main"
iocmonrepobeta="https://raw.githubusercontent.com/ViktorJp/IOCMON/develop"
iocmonreposcriptstable="https://github.com/ViktorJp/IOCMON/releases/latest/download/iocmon.sh"

# AMTM Email Notification Variables - shared library reused verbatim from TAILMON/VPNMON-R3
readonly scriptFileName="${0##*/}"  # this script's own filename
readonly scriptFileNTag="${scriptFileName%.*}"  # filename without extension
readonly CEM_LIB_TAG="master"   # branch of the CustomMiscUtils repo to pull the email library from
readonly CEM_LIB_URL="https://raw.githubusercontent.com/Martinski4GitHub/CustomMiscUtils/${CEM_LIB_TAG}/EMail"  # download URL for the shared email library
readonly CUSTOM_EMAIL_LIBDir="/jffs/addons/shared-libs"  # where the shared AMTM email library lives
readonly CUSTOM_EMAIL_LIBName="CustomEMailFunctions.lib.sh"  # shared AMTM email library filename
readonly CUSTOM_EMAIL_LIBFile="${CUSTOM_EMAIL_LIBDir}/$CUSTOM_EMAIL_LIBName"  # full path to the shared email library
readonly emailwrapwidth=60  # alert email line width; the library's <pre> wrapper never wraps lines itself

# -------------------------------------------------------------------------------------------------------------------------
# Config schema defaults - these are overwritten by $config once it exists

timerloop=60                    # main loop interval, sec
feedupdatehrs=4                 # IoC feed refresh cadence
fsintegrityhrs=6                # filesystem baseline diff cadence (independent of timerloop)

enablethreatfox=0               # enable the ThreatFox feed source (needs an abuse.ch Auth-Key)
threatfoxapikey=""              # abuse.ch Auth-Key from auth.abuse.ch (one key works for ThreatFox and URLhaus)
enablespamhaus=1                # enable the Spamhaus DROP/EDROP feed source
enablefeodo=1                   # enable the Feodo Tracker feed source
enablenetapi=1                  # enable the NetAPI.com compromised IP/domain feed source (no key needed)
enableurlhaus=0                 # enable the URLhaus feed source (needs an abuse.ch Auth-Key)
urlhausapikey=""                # abuse.ch Auth-Key from auth.abuse.ch (one key works for ThreatFox and URLhaus)
enableqfeeds=0                  # enable the Q-Feeds OSINT IP/domain feed source (needs an API token)
qfeedsapikey=""                 # Q-Feeds API token from tip.qfeeds.com (free Community license works)
qfeedshrs=24                    # Q-Feeds refresh cadence in hours (the free feed only changes about daily)
enableabuseipdb=0               # look up each flagged public IP in AbuseIPDB's /api/v2/check reputation endpoint (needs an API key)
abuseipdbapikey=""              # AbuseIPDB API key from abuseipdb.com (free tier = 1,000 checks/day)
abuseipdbcachehrs=24            # hours a cached AbuseIPDB result is reused before the same IP is looked up again
abuseipdbmaxage=30              # AbuseIPDB maxAgeInDays - how many days of abuse reports each lookup covers (1-365)
abuseipdbdailymax=900           # self-imposed daily AbuseIPDB lookup ceiling, kept under the plan's own daily limit
abuseipdbcyclemax=10            # most AbuseIPDB lookups made in any one scan cycle

enablednswatch=0                # tail dnsmasq log for domain matches against feed data - off by default so a fresh install doesn't start "awaiting dnsmasq setup"
dnsexceptions=""                # space-separated domains that match a feed but never alert/email, just an INFO log line - for known false positives
dnslogpath=""                   # optional explicit DNS query log file (e.g. a syslog-ng/scribe dnsmasq.log) - blank = auto-detect
dnsforcefilelog=0               # force dnsmasq to log queries to a plain file (log-facility=) instead of syslog - workaround for a router where dnsmasq can't reach syslog at all
dnsquerylogmaxkb=1024           # dnsforcefilelog's own query log file is rotated once it reaches this size, in KB
dnsquerylogkeep=2               # how many rotated generations (dnsmasq_queries.log.1, .2, ...) to keep before the oldest is deleted
enablednstunnel=0               # behavioral DNS-tunneling/exfiltration heuristic (query volume/name-length patterns, not feed-based) - off by default
dnstunnelsubthreshold=20        # distinct subdomains under one base domain from one source IP, within a single check tick, to flag as possible tunneling
dnstunnelnamelen=60             # a single query name at or above this length (chars) is flagged on its own, regardless of repetition
dnssource="auto"                # auto = AdGuard Home when it is running and owns port 53, else dnsmasq | dnsmasq | adguardhome
aghurl=""                       # AdGuard Home web/API base URL - blank = read from AdGuardHome.yaml (http.address)
aghurl2=""                      # backup AdGuard Home base URL, read only when the first one fails - blank = no backup
aghcred2=""                     # backup AdGuard Home "user:password" login, encoded the same way as aghcred
aghincludeblocked=0             # 1 = also check queries AdGuard Home already blocked (they never left the network)
aghpagesize=500                 # query-log entries fetched per API call
aghmaxpages=20                  # most API pages read per cycle before giving up and warning about a gap
aghcred=""                      # AdGuard Home "user:password" login, base64-encoded with openssl (encoded, not encrypted)
aghauthfile="/jffs/addons/iocmon.d/agh.auth"  # legacy login file, moved into aghcred at startup
aghreplyfile="/tmp/iocmon_agh_replies"  # "domain|ip" answers seen recently, RAM only, for dnsreplyip
selfqpaths="/tmp/astraea/selfq /tmp/kairos/selfq"  # Astraea's and Kairos's own router lookups ("name|type|epoch", RAM, 2 hours), read only
kairosstatusfile="/tmp/kairos/status"  # Kairos's key=value state (time, dns, updated, version), read only
emailfallbacksubject="ALERT: IOCMON could not deliver a security alert"  # notice sent when an alert email is rejected
selfqseenfile="/tmp/iocmon_selfq_seen"  # "name epoch" of set-aside lookups already logged, so each is logged once per 6 hours
logtrimstamp="/tmp/iocmon_logtrim.last"  # time of the last 6-hourly activity log rotation check
logkeep=2                       # rotated copies kept per log (.1 newest, .2 oldest)
timeoutcmd=""                   # "timeout " once Entware's /opt/bin/timeout is found, for nvram and cru calls
timeoutsec=""                   # seconds before a hung nvram or cru call is killed
timeoutlng=""                   # longer limit for slower commands
timeoutpkg="coreutils-timeout"  # Entware package that provides /opt/bin/timeout
LAN_HostName=""                 # router's lan_hostname, read once and reused by every log line
astraeascript="/jffs/scripts/astraea.sh"  # Astraea, asked for its certificate verdict on an alerted name or address
astraealogmark="# Astraea: site names for certificate checks"  # marker line Astraea writes above its own log-queries in dnsmasq.conf.add
astraeaintelfile="/tmp/iocmon_astraea_intel"  # "target<TAB>verdict<TAB>reason" of recent Astraea verdicts, RAM only, for alert emails
aghyamlpaths="/opt/etc/AdGuardHome/AdGuardHome.yaml /opt/etc/AdGuardHome.yaml /jffs/addons/AdGuardHome.d/AdGuardHome.yaml"
enableconntrackwatch=1          # poll nf_conntrack for IP matches
ipexceptions=""                 # space-separated single IPs or CIDR ranges never matched against a feed by checkconntrack
enableskynetimport=0            # push current IPv4 feed indicators into Skynet Firewall's own ban list, tagged IOCMON - see syncskynetimport()
skynetimportqfeeds=0            # also include Q-Feeds' much larger, lower-confidence OSINT IP list in that Skynet import
enablefwlogwatch=0              # requires an iptables LOG rule; setup menu can add it
enableauthwatch=1               # dropbear/httpd brute-force detection, no feed dependency
authfailthreshold=5             # same-source-IP login failures within ONE check tick to trigger a burst alert
authslowwindowhrs=24            # sliding window, in hours, for the low-and-slow brute-force detector below
authslowthreshold=15            # same-source-IP login failures across that whole window to trigger a sustained alert

enablefsintegrity=1
fsmodalertmode="mod"            # "mod" alerts on any mtime/size change to a critical path; "hash" additionally requires the file's own content hash to have actually changed
fswatchdirs="/jffs/scripts /jffs/configs /jffs/addons /jffs/.ssh /tmp/mnt/$extdrivelabel"  # /opt/bin,/opt/sbin,etc. deliberately excluded - already covered via the drive-root watch
fswatchexclude="Backups Downloads Media iocmon.d"  # folder NAMES excluded by name anywhere under a watched tree - not a substitute for checkfsintegrity's own iocmonroot self-exclusion
fsexcludeext=".log .csv .txt .db"  # file EXTENSIONS excluded from every fs-integrity check (new/modified/deleted/permission/hash alike) - leading "." optional
fsexcludefiles=""               # individual absolute file paths excluded from every fs-integrity check - empty by default
fsmaxhashsize=52428800          # 50MB cap - skip larger files for auto-hash
enablequarantine=0              # opt-in; renames + strips +x, never deletes
enablecrondiff=1                # alert on unexpected new cru entries and Entware crontab entries
cronexceptions=""               # newline-separated (not space-separated) exact cron-line matches that never alert - see cronmatchkey() for the schedule-agnostic comparison
enablenvramwatch=1              # diff a hardcoded security-relevant NVRAM watchlist every tick - see $nvramwatchvars below
enablefwrulediff=1              # alert on unexpected new port-forward/DMZ/UPnP NAT rules - see checkfirewallrules()
enablefsdeletionwatch=1         # alert when a file disappears from the same critical paths that already alert on an addition/edit
enablepermwatch=0               # detect a write/execute bit added to an already-known file with unchanged content/mtime - off by default, costs one fork per watched file per scan
enableetccritical=1             # always-alert content-hash watch over a short list of high-value /etc files/dirs (accounts, pam.d, certs, VPN secrets) - see checketccritical()
etccriticalpaths="/etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/passwd.custom /etc/passwd.static /etc/passwd.openvpn /etc/group.custom /etc/group.static /etc/shadow.chilli /etc/shadow.openvpn /etc/profile /etc/pam.d /etc/ld.so.conf /etc/ipsec.secrets /etc/openssl.cnf /etc/cacert.pem /etc/cacert_gen.pem /etc/cakey.pem /etc/cakey_gen.pem /etc/cert.pem /etc/cert_gen.pem /etc/cert.crt /etc/key.pem /etc/key_gen.pem /etc/server.pem /etc/ipsec.conf /etc/ipsec.d /etc/strongswan.conf /etc/strongswan.d /etc/swanctl /etc/wg /etc/openvpn"  # absolute files/dirs - a missing entry (unused subsystem) is silently skipped

extdrivelabel=""                # resolved USB label, not the live path - drive resolution lands in a later phase

enablealertemail=1              # send an AMTM email whenever a real IOC detection fires
alertbanneratbottom=0           # 0 = SECURITY ALERT banner at top of screen (default), 1 = just above the timer line
alertlevel=""                   # "all" = banner/email for every alert, "critical" = only Critical ones; blank = migrate from alertfeedonly
alertfeedonly=0                 # legacy key from before alertlevel, read once by migratealertlevel and no longer saved
dnsescalatescore=75             # a DNS feed match becomes Critical when AbuseIPDB scores its reply IP at or above this (1-100)
dnssharedhosts="github.com githubusercontent.com microsoft.com windows.net live.com office.com amazonaws.com cloudfront.net googleapis.com googleusercontent.com gstatic.com apple.com icloud.com steamcommunity.com steampowered.com roblox.com discord.com discordapp.com dropbox.com dropboxusercontent.com akamaized.net in-addr.arpa ip6.arpa"  # shared-hosting domains (and subdomains) whose DNS feed matches are logged as Info
ratelimit=0                     # max emails/hour, 0 = unlimited
logsize=2000                    # lines at which $logfile and the other logs rotate to .1 (0 = never)
logfilepath="$jffslogfile"      # configured activity log location: JFFS default, or $iocmonroot/state/iocmon.log on the external drive
autostart=0                     # launch the background monitor via post-mount on boot
schedule=1                      # run IOCMON's own daily self-update check via cron
schedulehrs=4                   # hour of day for the daily self-update check
schedulemin=0                   # minute of hour for the daily self-update check
updateiocm=0                    # autoupdate IOCMON script itself
track=0                         # update track: 0 = stable, 1 = beta
enablewebui=0                   # add the IOCMON tab to the router web interface
otxreportsort="frequency"       # OTX AlienVault Threat Report sort order: "frequency" (one row per IP, most-matched first) or "date" (every occurrence, newest first)

# Well-known Merlin persistent filenames living directly in /jffs/scripts
fsstartupscripts="services-start services-stop service-event service-event-end firewall-start wan-start wan-event nat-start pre-mount post-mount unmount init-start dhcpc-event openvpn-event ddns-start update-notification qos-start wgserver-start wgserver-stop wgclient-start wgclient-stop wg-event"

# Security-relevant NVRAM variables checknvram() diffs every main-loop tick
nvramruntimevars="wan_dns wan0_dns wan1_dns"  # watched vars the firmware rewrites itself on a WAN reconnect or DHCP renewal - their changes are Warning, not Critical
nvramwatchvars="sshd_enable sshd_forwarding sshd_pass sshd_port sshd_port_x sshd_authkeys telnetd_enable wan_dns wan_dnsenable_x wan_dns1_x wan_dns2_x wan0_dns wan0_dnsenable_x wan0_dns1_x wan0_dns2_x wan1_dns wan1_dnsenable_x wan1_dns1_x wan1_dns2_x dhcp_dns1_x dhcp_dns2_x ipv6_dnsenable ipv6_dns1 ipv6_dns2 ipv6_dns3 ipv6_dns1_x dnspriv_enable dnspriv_rulelist wan_proto wan0_proto wan1_proto jffs2_scripts dmz_ip vts_enable_x vts_rulelist vts_upnplist autofw_enable_x autofw_rulelist"

# -------------------------------------------------------------------------------------------------------------------------
# Color variables - reused verbatim from BACKUPMON/STUNMON/TAILMON/VPNMON-R3, etc.

CBlack="\e[1;30m"
InvBlack="\e[1;40m"
CRed="\e[1;31m"
InvRed="\e[1;41m"
CGreen="\e[1;32m"
InvGreen="\e[1;42m"
CDkGray="\e[1;90m"
InvDkGray="\e[1;100m"
InvLtGray="\e[1;47m"
CYellow="\e[1;33m"
InvYellow="\e[1;43m"
CBlue="\e[1;34m"
InvBlue="\e[1;44m"
CMagenta="\e[1;35m"
CCyan="\e[1;36m"
InvCyan="\e[1;46m"
CWhite="\e[1;37m"
InvWhite="\e[1;107m"
CClear="\e[0m"

# -------------------------------------------------------------------------------------------------------------------------
# Menu numbering - single source of truth so a Configuration Menu reorder never desyncs the Advanced Settings submenus

advsettingsmenunum=10  # Configuration Menu item # for "Advanced Settings" - every 9.x-style submenu/sub-item title below derives from this

# -------------------------------------------------------------------------------------------------------------------------
# FUNCTIONS BEGIN
# -------------------------------------------------------------------------------------------------------------------------

# -------------------------------------------------------------------------------------------------------------------------
# LogoNM/LogoNMexit display the IOCMON name in ASCII art with the two-tone flash used by the sibling scripts

logoNM ()
{
  clear
  echo ""
  echo ""
  echo ""
  echo -e "${CDkGray}                    ________  ________  _______  _   __"
  echo -e "                   /  _/ __ \\/ ____/  |/  / __ \\/ | / /"
  echo -e "                   / // / / / /   / /|_/ / / / /  |/ / "
  echo -e "                 _/ // /_/ / /___/ /  / / /_/ / /|  /  "
  echo -e "                /___/\\____/\\____/_/  /_/\\____/_/ |_/  v$version"
  echo ""
  echo ""
  printf "\r                       ${CGreen}    [ INITIALIZING ]     ${CClear}"
  sleep 1
  clear
  echo ""
  echo ""
  echo ""
  echo -e "${CYellow}                    ________  ________  _______  _   __"
  echo -e "                   /  _/ __ \\/ ____/  |/  / __ \\/ | / /"
  echo -e "                   / // / / / /   / /|_/ / / / /  |/ / "
  echo -e "                 _/ // /_/ / /___/ /  / / /_/ / /|  /  "
  echo -e "                /___/\\____/\\____/_/  /_/\\____/_/ |_/  v$version"
  echo ""
  echo ""
  printf "\r                       ${CGreen}[ INITIALIZING ... DONE ]${CClear}"
  sleep 1
  printf "\r                       ${CGreen}      [ LOADING... ]     ${CClear}"
  sleep 1
}

logoNMexit ()
{
  clear
  echo ""
  echo ""
  echo ""
  echo -e "${CYellow}                    ________  ________  _______  _   __"
  echo -e "                   /  _/ __ \\/ ____/  |/  / __ \\/ | / /"
  echo -e "                   / // / / / /   / /|_/ / / / /  |/ / "
  echo -e "                 _/ // /_/ / /___/ /  / / /_/ / /|  /  "
  echo -e "                /___/\\____/\\____/_/  /_/\\____/_/ |_/  v$version"
  echo ""
  echo ""
  printf "\r                       ${CGreen}    [ SHUTTING DOWN ]     ${CClear}"
  sleep 1
  clear
  echo ""
  echo ""
  echo ""
  echo -e "${CDkGray}                    ________  ________  _______  _   __"
  echo -e "                   /  _/ __ \\/ ____/  |/  / __ \\/ | / /"
  echo -e "                   / // / / / /   / /|_/ / / / /  |/ / "
  echo -e "                 _/ // /_/ / /___/ /  / / /_/ / /|  /  "
  echo -e "                /___/\\____/\\____/_/  /_/\\____/_/ |_/  v$version"
  echo ""
  echo ""
  printf "\r                       ${CGreen}    [ SHUTTING DOWN ]     ${CClear}"
  sleep 1
  printf "\r                       ${CDkGray}      [ GOODBYE... ]     ${CClear}\n\n"
  sleep 1
}

# -------------------------------------------------------------------------------------------------------------------------
# _SetUpTimeoutCmdVars_ turns on the timeout shim for nvram and cru calls once Entware's timeout binary is present

_SetUpTimeoutCmdVars_()
{
   if [ -z "${timeoutcmd:+xSETx}" ] && [ -f "/opt/bin/timeout" ]
   then
       timeoutcmd="timeout "
       timeoutsec="10"
       timeoutlng="60"
   fi
}

# -------------------------------------------------------------------------------------------------------------------------
# nvramtimeoutlog logs one hung nvram or cru call, without calling nvram again for the hostname

nvramtimeoutlog()
{
  echo -e "$(date +'%b %d %Y %X') ${LAN_HostName:-$(uname -n 2>/dev/null)} IOCMON[$$] - WARNING: '$1' did not answer within ${timeoutsec}s and was stopped - $2." >> "$logfile"
}

# -------------------------------------------------------------------------------------------------------------------------
# nvramget reads NVRAM value $1 into $nvramval through timeout, reusing the last value read if the call hangs (returns 1 if none)

nvramget()
{
  local key rc
  case "$1" in *[!A-Za-z0-9_]*) key="$(printf '%s' "$1" | tr -c 'A-Za-z0-9_' '_')" ;; *) key="$1" ;; esac
  nvramval="$($timeoutcmd$timeoutsec nvram get "$1" 2>/dev/null)"
  rc=$?
  if [ "$rc" = 124 ] || [ "$rc" = 137 ]; then
    if eval "[ -n \"\${nvc_$key+x}\" ]"; then
      eval "nvramval=\"\$nvc_$key\""
      nvramtimeoutlog "nvram get $1" "using the last value read"
      return 0
    fi
    nvramval=""
    nvramtimeoutlog "nvram get $1" "no earlier value to fall back on"
    return 1
  fi
  eval "nvc_$key=\$nvramval"
  return 0
}

# -------------------------------------------------------------------------------------------------------------------------
# crul reads 'cru l' into $cruout through timeout, reusing the last list read if the call hangs (returns 1 if none)

crul()
{
  local rc
  cruout="$($timeoutcmd$timeoutsec cru l 2>/dev/null)"
  rc=$?
  if [ "$rc" = 124 ] || [ "$rc" = 137 ]; then
    if [ -n "${crucache+x}" ]; then
      cruout="$crucache"
      nvramtimeoutlog "cru l" "using the last list read"
      return 0
    fi
    cruout=""
    nvramtimeoutlog "cru l" "no earlier list to fall back on"
    return 1
  fi
  crucache="$cruout"
  return 0
}

# -------------------------------------------------------------------------------------------------------------------------
# _SetLAN_HostName_ reads lan_hostname once, falling back to the kernel hostname if nvram hangs

_SetLAN_HostName_()
{
  [ -n "${LAN_HostName:+xSETx}" ] && return
  nvramget lan_hostname
  LAN_HostName="${nvramval:-$(uname -n 2>/dev/null)}"
}

# -------------------------------------------------------------------------------------------------------------------------
# _GetLAN_HostName_ prints the router's hostname for log lines

_GetLAN_HostName_()
{ _SetLAN_HostName_ ; echo "$LAN_HostName" ; }

# -------------------------------------------------------------------------------------------------------------------------
# Promptyn is a simple function that accepts y/n input

promptyn()
{   # No defaults, just y or n, confirmed with Enter
  while true; do
    read -p "$1" -r yn
    printf '\033[1A\033[%dC' "$(( ${#1} + ${#yn} ))"  # back to the end of the answer line, so callers lay out as with a single-key read
      case "${yn}" in
        [Yy]* ) return 0 ;;
        [Nn]* ) return 1 ;;
        * ) echo -e "\nPlease answer y or n.";;
      esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# openeditor opens $1 using the user's preferred $EDITOR (nano/vim/vi), falling back to nano - from BACKUPMON.

openeditor()
{
  local EDITFILE="$1"
  export TERM=linux

  if [ -z "$EDITOR" ]; then
    nano +999999 --linenumbers "$EDITFILE"
  elif echo "$EDITOR" | grep -qi "nano"; then
    nano +999999 --linenumbers "$EDITFILE"
  elif echo "$EDITOR" | grep -qi "vim"; then
    vim + +set\ nu "$EDITFILE"
  elif echo "$EDITOR" | grep -qi "vi"; then
    vi "$EDITFILE"
  else
    $EDITOR "$EDITFILE"
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# Spinner is a script that provides a small indicator on the screen to show script activity

spinner()
{
  spins=$1

  spin=0
  totalspins=$((spins / 4))
  while [ $spin -le $totalspins ]; do
    for spinchar in / - \\ \|; do
      printf "\r$spinchar"
      sleep 1
    done
    spin=$((spin+1))
  done

  printf "\r"
}

# -------------------------------------------------------------------------------------------------------------------------
# ScriptUpdateFromAMTM - borrowed from ExtremeFiretop/TAILMON; checks for and applies script updates via AMTM.

ScriptUpdateFromAMTM()
{
    if ! "$doScriptUpdateFromAMTM"
    then
        printf "Automatic script updates via AMTM are currently disabled.\n\n"
        return 1
    fi

    if [ $# -gt 0 ] && [ "$1" = "check" ]
    then return 0
    fi

    echo ""
    echo -e "${InvGreen} ${CClear} Downloading latest ${CGreen}IOCMON${CClear}...Please stand by while we enhance your router's security posture..."
    curl -fsSL "$iocmonreposcriptstable" -o "/jffs/scripts/iocmon.sh" && chmod 755 "/jffs/scripts/iocmon.sh"
    DLsuccess=$?
    if [ "$DLsuccess" -eq 0 ]; then
      touch "$restartpendingfile"
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: IOCMON updated via AMTM to v$(ondiskversion) - any running instance will restart into it." >> "$logfile"
      echo -e "${InvGreen} ${CClear} IOCMON Download/Update Success."
      echo ""
    else
      echo -e "${InvRed} ${CClear} IOCMON Download/Update Failed. Please check all the things."
      echo ""
    fi

    return "$DLsuccess"
}

# -------------------------------------------------------------------------------------------------------------------------
# downloadiocmonupdate does the actual curl-to-.new-then-mv download; shared by vupdate() and -autoupdate.

downloadiocmonupdate()
{
  local url="$1" label="$2" dlrc

  if [ "$label" = "STABLE" ]; then
    curl -fsSL "$iocmonreposcriptstable" -o "${apppath}.new"
    dlrc=$?
  else
    curl --silent --retry 3 --connect-timeout 10 --max-time 30 --retry-delay 1 --retry-all-errors --fail "$url" -o "${apppath}.new"
    dlrc=$?
  fi

  [ "$dlrc" -eq 0 ] && ! scriptfilevalid "${apppath}.new" && dlrc=255

  if [ "$dlrc" -eq 0 ]; then
    mv "${apppath}.new" "$apppath"
    chmod 755 "$apppath"
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: IOCMON updated to the $label track successfully." >> "$logfile"
    return 0
  else
    rm -f "${apppath}.new"
    if [ "$dlrc" -eq 255 ]; then
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - ERROR: The downloaded IOCMON $label script failed validation and was not installed." >> "$logfile"
    else
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - ERROR: IOCMON $label update download failed." >> "$logfile"
    fi
    [ "$dlrc" -eq 255 ] && return 2
    return 1
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# resolveupdatesource picks remoteurl/remotelabel/remoteversion for the subscribed track - Beta only pulls the develop branch once its version genuinely differs from Stable's, falling back to Stable otherwise.

resolveupdatesource()
{
  if [ "$track" = "1" ] && [ -n "$Bversion" ] && [ "$Bversion" != "$DLversion" ]; then
    remoteversion="$Bversion"; remotelabel="BETA"; remoteurl="$iocmonrepobeta/iocmon.sh"
  else
    remoteversion="$DLversion"; remotelabel="STABLE"; remoteurl="$iocmonrepostable/iocmon.sh"
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# ondiskversion prints the version="..." value of the script file currently on disk (default $apppath).

ondiskversion()
{
  sed -n 's/^version="\(.*\)"[[:space:]]*$/\1/p' "${1:-$apppath}" 2>/dev/null | head -n1
}

# -------------------------------------------------------------------------------------------------------------------------
# scriptfilevalid succeeds only if $1 is a non-empty, syntactically valid IOCMON script carrying a version line.

scriptfilevalid()
{
  [ -s "$1" ] || return 1
  [ -n "$(ondiskversion "$1")" ] || return 1
  sh -n "$1" >/dev/null 2>&1
}

# -------------------------------------------------------------------------------------------------------------------------
# checkscriptreplaced restarts the running loop into $apppath if a restart was flagged or the on-disk version differs from this process's.

checkscriptreplaced()
{
  local diskver reason sizebefore

  [ -f "$updatingfile" ] && return 0
  diskver="$(ondiskversion)"
  if [ -f "$restartpendingfile" ]; then
    reason="a newer IOCMON version was downloaded by an update"
  elif [ -n "$diskver" ] && [ "$diskver" != "$version" ]; then
    reason="the IOCMON script on disk was replaced (running v$version, on disk v$diskver)"
  else
    return 0
  fi

  sizebefore="$(wc -c < "$apppath" 2>/dev/null | tr -d ' ')"
  sleep 3
  [ "$(wc -c < "$apppath" 2>/dev/null | tr -d ' ')" = "$sizebefore" ] || return 0
  if ! scriptfilevalid "$apppath"; then
    if [ "$scriptreplacewarned" -eq 0 ]; then
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: Detected that $reason, but $apppath failed validation - staying on v$version until a valid copy is in place." >> "$logfile"
      scriptreplacewarned=1
    fi
    return 0
  fi

  rm -f "$restartpendingfile"
  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Detected that $reason - restarting into v${diskver} now." >> "$logfile"
  clear
  if [ "$diskver" = "$version" ]; then
    echo -e "${CGreen}An updated copy of IOCMON v${diskver} was installed - restarting into it...${CClear}"
  else
    echo -e "${CGreen}IOCMON v${diskver} was installed while v$version was running - restarting into the new version...${CClear}"
  fi
  sleep 2
  exec sh "$apppath" -noswitch
}

# -------------------------------------------------------------------------------------------------------------------------
# Preparebar and Progressbar provide the standard IOCMON key+Enter progress prompt (adapted from TAILMON)

preparebar()
{
  barlen=$1
  barspaces=$(printf "%*s" "$1")
  barchars=$(printf "%*s" "$1" | tr ' ' "$2")
}

# Read exactly one visible menu command followed by Enter.
readmenucommand()
{
  key_press=""
  menu_line_submitted=0
  ttydev="$(tty 2>/dev/null)"

  if [ -z "$ttydev" ] || [ "$ttydev" = "not a tty" ]; then
    return 1
  fi

  if IFS= read -r -t 1 key_press < "$ttydev"; then
    menu_line_submitted=1
    case "$key_press" in
      ?) return 0 ;;
      [Rr]!) return 0 ;;
      *) return 1 ;;
    esac
  fi

  key_press=""
  return 1
}

drawprogressprompt()
{
  local status_text="$1"
  local input_text="$2"

  laststatustext="$status_text"
  lastinputtext="$input_text"

  if [ "$progressfirstdraw" -eq 1 ]; then
    printf "\033[u\033[0J%b %s\033[2D" "$status_text" "$input_text"
    progressfirstdraw=0
  else
    printf "\033[s\r%b\033[u" "$status_text"
  fi
}

resetinvalidprogressinput()
{
  printf "\033[1A\33[2K\r%b %s\033[2D" "$laststatustext" "$lastinputtext"
}

progressbaroverride()
{
  insertspc=" "

  if [ $1 -eq -1 ]; then
    printf "\r  $barspaces\r"
  else
    if [ ! -z $7 ] && [ $1 -ge $7 ]; then
      barch=$(($7*barlen/$2))
      barsp=$((barlen-barch))
      progr=$((100*$1/$2))
    else
      barch=$(($1*barlen/$2))
      barsp=$((barlen-barch))
      progr=$((100*$1/$2))
    fi

    if [ ! -z $6 ]; then AltNum=$6; else AltNum=$1; fi

    if [ "$5" == "Standard" ]; then
      tlwidth=${#2}
      AltNumPadded=$(printf "%0${tlwidth}d" "$AltNum")
      progrPadded=$(printf "%03d" "$progr")
      if [ "$timerpaused" -eq 1 ]; then timerinv="$InvRed"; else timerinv="$InvDkGray"; fi
      drawprogressprompt "${InvGreen} ${CClear} ${CWhite}${timerinv}${AltNumPadded}${4} / ${progrPadded}%${CClear} [${CGreen}c${CClear}=Config] [${CGreen}f${CClear}=Feeds] [${CGreen}i${CClear}=FS Integrity] [${CGreen}t${CClear}=Test] [${CGreen}a${CClear}=Ack] [${CGreen}l${CClear}=Logs] [${CGreen}p${CClear}=Pause] [${CGreen}x${CClear}=Detach/Screen] [${CGreen}e${CClear}=Exit]${CClear}" "[Key+Enter?  ]"
    fi
  fi

  if readmenucommand; then
      echo ""
      case $key_press in
          [Cc]) vsetup;;
          [Ff]) forcefeeds;;
          [Ii]) forcefsintegrity;;
          [Vv]) vioclog;;
          1) vfslastfile 1;;
          2) vfslastfile 2;;
          3) vfslastfile 3;;
          4) vfslastfile 4;;
          [Dd]) alertviewmode="dropbear"; renderdashboard;;
          [Oo]) alertviewmode="ioc"; renderdashboard;;
          [Hh]) alertviewmode="hash"; renderdashboard;;
          [Uu]) alertviewmode="reputation"; renderdashboard;;
          [Rr]) clearcurrentlog;;
          [Rr]!) clearcurrentlognow;;
          [Zz]) addtodnsexception;;
          [Nn]) if [ "$alertviewmode" = "ioc" ]; then votxreport quick; fi; renderdashboard;;
          [Tt]) testdetection;;
          [Aa]) acknowledgealert;;
          [Ll]) vlogs;;
          [Pp]) if [ "$timerpaused" -eq 1 ]; then timerpaused=0; else timerpaused=1; fi; renderdashboard;;
          [Xx]) timerpaused=0; renderdashboard; [ -x /opt/sbin/screen ] && /opt/sbin/screen -S iocmon -X detach;;
          [Ee])
            clear
            echo -e "${CGreen}[Exit IOCMON]${CClear}"
            echo ""
            if promptyn "Are you sure you wish to Exit (Y/N): "; then
              logoNMexit; echo -e "${CClear}\n"; exit 0
            fi
            renderdashboard
            ;;
          *) if [ "$timerpaused" -eq 1 ]; then renderdashboard; else timer=$timerloop; fi;;
      esac
  elif [ "$menu_line_submitted" -eq 1 ]; then
      resetinvalidprogressinput
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# booleantoyesno renders a 0/1 config value as a colored YES/NO toggle-switch for menu display

booleantoyesno()
{
  if [ "$1" -eq 1 ]; then
    echo "${CGreen}YES${CClear} |${InvGreen}  ${CClear}  | ${CDkGray}NO${CClear}"
  else
    echo "${CDkGray}YES${CClear} |  ${InvRed}  ${CClear}| ${CRed}NO${CClear}"
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# stripansi removes color escape codes from $1, leaving only its visible text

stripansi()
{
  local esc
  esc="$(printf '\033')"
  printf '%b' "$1" | sed "s/${esc}\[[0-9;]*m//g"
}

# -------------------------------------------------------------------------------------------------------------------------
# padright prints a (possibly color-coded) string followed by however many spaces bring its VISIBLE width up to $2

padright()
{
  local text="$1" width="$2" stripped visiblelen pad
  stripped="$(stripansi "$text")"
  visiblelen=${#stripped}
  pad=$((width - visiblelen))
  [ "$pad" -lt 1 ] && pad=1
  printf '%b' "$text"
  printf '%*s' "$pad" ""
}

# -------------------------------------------------------------------------------------------------------------------------
# menurow prints one numbered Advanced Settings row, dimmed (and inert to its own case arm) when $5 is 0

menurow()
{
  local badge="$1" label="$2" value="$3" width="${4:-68}" enabled="${5:-1}"
  if [ "$enabled" -eq 1 ]; then
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}${badge}${CClear} : "
    padright "$label" "$width"
    echo -e ": $value"
  else
    echo -en "${InvGreen} ${CClear} ${CDkGray}${badge}${CClear} : "
    padright "${CDkGray}${label}${CClear}" "$width"
    echo -e ": ${CDkGray}$(stripansi "$value")${CClear}"
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# blanklineguard leaves exactly one blank line before whatever comes next

blanklineguard()
{
  printf '\33[2K\r\n'
}

# -------------------------------------------------------------------------------------------------------------------------
# fsscanprogress prints a single in-place-overwriting status line

fsscanprogress()
{
  local label="$1" current="$2" total="$3" pct=""
  if [ -n "$total" ] && [ "$total" -gt 0 ] 2>/dev/null; then
    pct=" ($((current * 100 / total))%)"
  fi
  printf '\33[2K\r  %b*%b %s: %s/%s%s...' "$CGreen" "$CClear" "$label" "$current" "$total" "$pct"
}

# -------------------------------------------------------------------------------------------------------------------------
# inlinestatus prints a single in-place-overwriting "label..." status line, no count/percent

inlinestatus()
{
  printf '\33[2K\r  %b*%b %s...' "$CGreen" "$CClear" "$1"
}

# -------------------------------------------------------------------------------------------------------------------------
# skynetprogress prints an in-place "Skynet import: label (step/total, pct%)..." status line

skynetprogress()
{
  local step="$1" total="$2" label="$3" pct
  pct=$((step * 100 / total))
  printf '\33[2K\r  %b*%b Skynet import: %s (%s/%s, %s%%)...' "$CGreen" "$CClear" "$label" "$step" "$total" "$pct"
}

# -------------------------------------------------------------------------------------------------------------------------
# lastalertsummary reads the most recent "IOC match" log line and echoes "HH:MM kind: indicator", or "none yet".

lastalertsummary()
{
  local line
  line="$(logall "$logfile" | grep "WARNING: IOC match" | tail -1)"
  if [ -z "$line" ]; then
    echo "none yet"
    return
  fi
  echo "$line" | sed -E 's/^[A-Za-z]+ [0-9]+ [0-9]+ ([0-9:]+) .*IOC match \(([a-z]+)\): ([^ ]+).*/\1 \2: \3/'
}

alertstoday()
{
  logall "$logfile" | grep "$(date +'%b %d %Y')" | grep -c "WARNING: IOC match"
}

# -------------------------------------------------------------------------------------------------------------------------
# vercompare returns gt/lt/eq comparing two dotted version strings

vercompare()
{
  awk -v v1="$1" -v v2="$2" 'BEGIN {
    n1=split(v1,a,".")
    n2=split(v2,b,".")
    n=(n1>n2)?n1:n2
    for(i=1;i<=n;i++) {
      x=(i<=n1)?a[i]+0:0
      y=(i<=n2)?b[i]+0:0
      if (x>y) { print "gt"; exit }
      if (x<y) { print "lt"; exit }
    }
    print "eq"
  }'
}

# -------------------------------------------------------------------------------------------------------------------------
# updatecheck/betacheck download the version files from each track and flag a banner on mismatch

updatecheck()
{
  UpdateNotify=0
  curl --silent --retry 3 --connect-timeout 10 --max-time 30 --retry-delay 1 --retry-all-errors --fail "$iocmonrepostable/version.txt" -o "$dlverpath"

  if [ -f "$dlverpath" ]; then
    DLversion=$(cat "$dlverpath")

    if [ "$track" == "1" ]; then
      UpdateNotify=0
    elif [ "$DLversion" != "$version" ]; then
      DLversionPF=$(printf "%-8s" "$DLversion")
      versionPF=$(printf "%-8s" "$version")
      UpdateNotify="${InvYellow} ${InvDkGray}${CWhite} Stable Track Update available: v$versionPF -> v$DLversionPF                                                                                   ${CClear}"
    else
      UpdateNotify=0
    fi
  fi
}

betacheck()
{
  BUpdateNotify=0
  curl --silent --retry 3 --connect-timeout 10 --max-time 30 --retry-delay 1 --retry-all-errors --fail "$iocmonrepobeta/version.txt" -o "$bverpath"

  if [ -f "$bverpath" ]; then
    Bversion=$(cat "$bverpath")

    if [ "$track" == "1" ] && [ "$Bversion" != "$version" ]; then
      BversionPF=$(printf "%-8s" "$Bversion")
      versionPF=$(printf "%-8s" "$version")
      BUpdateNotify="${InvYellow} ${InvDkGray}${CWhite} Beta Track Update available: v$versionPF -> v$BversionPF                                                                                     ${CClear}"
    else
      BUpdateNotify=0
    fi
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# migratealertlevel fills a blank or unknown alertlevel from the legacy alertfeedonly key (1 = critical, else all)

migratealertlevel()
{
  case "$alertlevel" in
    all|critical) ;;
    *) if [ "$alertfeedonly" = "1" ]; then alertlevel="critical"; else alertlevel="all"; fi ;;
  esac
}

# -------------------------------------------------------------------------------------------------------------------------
# saveconfig writes the current in-memory config out to iocmon.cfg, then sources it back immediately

saveconfig()
{
  migratealertlevel
  { echo 'timerloop='$timerloop
    echo 'feedupdatehrs='$feedupdatehrs
    echo 'fsintegrityhrs='$fsintegrityhrs

    echo 'enablethreatfox='$enablethreatfox
    echo 'threatfoxapikey="'"$threatfoxapikey"'"'
    echo 'enablespamhaus='$enablespamhaus
    echo 'enablefeodo='$enablefeodo
    echo 'enablenetapi='$enablenetapi
    echo 'enableurlhaus='$enableurlhaus
    echo 'urlhausapikey="'"$urlhausapikey"'"'
    echo 'enableqfeeds='$enableqfeeds
    echo 'qfeedsapikey="'"$qfeedsapikey"'"'
    echo 'qfeedshrs='$qfeedshrs
    echo 'enableabuseipdb='$enableabuseipdb
    echo 'abuseipdbapikey="'"$abuseipdbapikey"'"'
    echo 'abuseipdbcachehrs='$abuseipdbcachehrs
    echo 'abuseipdbmaxage='$abuseipdbmaxage
    echo 'abuseipdbdailymax='$abuseipdbdailymax
    echo 'abuseipdbcyclemax='$abuseipdbcyclemax

    echo 'enablednswatch='$enablednswatch
    echo 'dnsexceptions="'"$dnsexceptions"'"'
    echo 'dnslogpath="'"$dnslogpath"'"'
    echo 'dnsforcefilelog='$dnsforcefilelog
    echo 'dnsquerylogmaxkb='$dnsquerylogmaxkb
    echo 'dnsquerylogkeep='$dnsquerylogkeep
    echo 'enablednstunnel='$enablednstunnel
    echo 'dnstunnelsubthreshold='$dnstunnelsubthreshold
    echo 'dnstunnelnamelen='$dnstunnelnamelen
    echo 'dnssource="'"$dnssource"'"'
    echo 'aghurl="'"$aghurl"'"'
    echo 'aghcred="'"$aghcred"'"'
    echo 'aghurl2="'"$aghurl2"'"'
    echo 'aghcred2="'"$aghcred2"'"'
    echo 'aghincludeblocked='$aghincludeblocked
    echo 'aghpagesize='$aghpagesize
    echo 'aghmaxpages='$aghmaxpages
    echo 'enableconntrackwatch='$enableconntrackwatch
    echo 'ipexceptions="'"$ipexceptions"'"'
    echo 'enableskynetimport='$enableskynetimport
    echo 'skynetimportqfeeds='$skynetimportqfeeds
    echo 'enablefwlogwatch='$enablefwlogwatch
    echo 'enableauthwatch='$enableauthwatch
    echo 'authfailthreshold='$authfailthreshold
    echo 'authslowwindowhrs='$authslowwindowhrs
    echo 'authslowthreshold='$authslowthreshold

    echo 'enablefsintegrity='$enablefsintegrity
    echo 'fsmodalertmode="'"$fsmodalertmode"'"'
    echo 'fswatchdirs="'"$fswatchdirs"'"'
    echo 'fswatchexclude="'"$fswatchexclude"'"'
    echo 'fsexcludeext="'"$fsexcludeext"'"'
    echo 'fsexcludefiles="'"$fsexcludefiles"'"'
    echo 'fsmaxhashsize='$fsmaxhashsize
    echo 'enablequarantine='$enablequarantine
    echo 'enablecrondiff='$enablecrondiff
    printf "cronexceptions='%s'\n" "$(printf '%s' "$cronexceptions" | sed "s/'/'\\\\''/g")"
    echo 'enablenvramwatch='$enablenvramwatch
    echo 'enablefwrulediff='$enablefwrulediff
    echo 'enablefsdeletionwatch='$enablefsdeletionwatch
    echo 'enablepermwatch='$enablepermwatch
    echo 'enableetccritical='$enableetccritical
    echo 'etccriticalpaths="'"$etccriticalpaths"'"'

    echo 'extdrivelabel="'"$extdrivelabel"'"'

    echo 'enablealertemail='$enablealertemail
    echo 'alertbanneratbottom='$alertbanneratbottom
    echo 'alertlevel="'"$alertlevel"'"'
    echo 'dnsescalatescore='$dnsescalatescore
    echo 'dnssharedhosts="'"$dnssharedhosts"'"'
    echo 'ratelimit='$ratelimit
    echo 'logsize='$logsize
    echo 'logfilepath="'"$logfilepath"'"'
    echo 'autostart='$autostart
    echo 'schedule='$schedule
    echo 'schedulehrs='$schedulehrs
    echo 'schedulemin='$schedulemin
    echo 'updateiocm='$updateiocm
    echo 'track='$track
    echo 'otxreportsort="'"$otxreportsort"'"'
    echo 'enablewebui='$enablewebui
  } > "$config"
  chmod 600 "$config"

  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: IOCMON config has been updated." >> "$logfile"

  if [ -f "$config" ]; then
    . "$config"
  fi
  resolvelogfile

  schedulecron
  autostart
  syncwebui
}

# -------------------------------------------------------------------------------------------------------------------------
# getdrivelabel resolves the USB label for a given mount point

getdrivelabel()
{
  local mp="$1" devsd devnode lbl=""

  devsd="$(awk -v mp="$mp" '$2==mp && $1 ~ /^\/dev\/sd/ {print $1; exit}' /proc/mounts)"
  devnode="${devsd##*/}"

  if [ -n "$devnode" ]; then
    nvramget "usb_path_${devnode}_label"
    lbl="$nvramval"
    if [ -z "$lbl" ] && which blkid >/dev/null 2>&1; then
      lbl="$(blkid "$devsd" 2>/dev/null | sed -n 's/.*LABEL="\([^"]*\)".*/\1/p')"
    fi
  fi

  echo "$lbl"
}

# -------------------------------------------------------------------------------------------------------------------------
# resolveiocmonroot computes the live USB path from the persisted label.

resolveiocmonroot()
{
  if [ -n "$extdrivelabel" ]; then
    iocmonroot="/tmp/mnt/${extdrivelabel}/iocmon.d"
  else
    iocmonroot=""
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# selectextdrive is the interactive USB drive picker

selectextdrive()
{
  setupbanner "1. IOCMON External Drive Selection" \
    "IOCMON stores IoC feed data and detection state on an external USB drive to avoid wearing out the router's internal flash storage. Small" \
    "control files stay on JFFS."

  mountpointpaths="$(awk '$1 ~ /^\/dev\/sd/ && $2 ~ /^\/tmp\/mnt\// {print $2}' /proc/mounts | sort -u)"

  if [ -z "$mountpointpaths" ]; then
    echo -e "${CRed}ERROR: No external USB drive was found mounted on this router.${CClear}"
    echo ""
    echo -e "IOCMON can still run in a ${CYellow}degraded JFFS-only mode${CClear}: small feed subsets only (e.g. Feodo's"
    echo -e "recommended list), no hash feeds, and no filesystem-integrity baseline."
    echo ""
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - ERROR: No external USB drive found. Degraded JFFS-only mode offered." >> "$logfile"
    echo -e "Continue in degraded JFFS-only mode?"
    if promptyn "[y/n]: "; then
      extdrivelabel=""
      resolveiocmonroot
      [ "$logfilepath" != "$jffslogfile" ] && relocatelogfile "$jffslogfile"
      saveconfig
      echo ""
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: Running in degraded JFFS-only mode (no external drive configured)." >> "$logfile"
      echo -e "${CYellow}IOCMON is now configured for degraded JFFS-only mode.${CClear}"
      echo ""
      read -rsp $'Press any key to continue...\n' -n1 key
      return 0
    else
      echo ""
      echo -e "${CClear}Setup cancelled."
      return 1
    fi
  fi

  mountpointcount="$(echo "$mountpointpaths" | wc -l)"

  if [ "$mountpointcount" -eq 1 ]; then
    candidatepath="$mountpointpaths"
    candidatelabel="$(getdrivelabel "$candidatepath")"
    echo -e "Found one external USB drive mounted at ${CGreen}$candidatepath${CClear} (label: ${CGreen}${candidatelabel:-unlabeled}${CClear})."
    echo ""
    echo -e "Use this drive for IOCMON?"
    if promptyn "[y/n]: "; then
      selecteddrivepath="$candidatepath"
    else
      echo ""
      echo -e "${CClear}Setup cancelled."
      return 1
    fi
  else
    echo -e "Multiple external USB drives were found:"
    echo ""
    listindex=0
    for mp in $mountpointpaths; do
      listindex=$((listindex+1))
      eval "mpidx_${listindex}=\"\$mp\""
      lbl="$(getdrivelabel "$mp")"
      echo -e "  ${InvDkGray}${CWhite}(${listindex})${CClear} : $mp (label: ${lbl:-unlabeled})"
    done
    echo ""
    while true; do
      read -p "Please select? (1-$listindex, e=Exit): " sel
      if [ "$sel" = "e" ] || [ "$sel" = "E" ] || [ -z "$sel" ]; then
        echo ""
        echo -e "${CClear}Setup cancelled."
        return 1
      fi
      if echo "$sel" | grep -qE "^[0-9]+$" && [ "$sel" -ge 1 ] && [ "$sel" -le "$listindex" ]; then
        eval "selecteddrivepath=\"\$mpidx_${sel}\""
        break
      fi
      echo -e "${CRed}Invalid selection.${CClear}"
    done
  fi

  extdrivelabel="$(getdrivelabel "$selecteddrivepath")"
  if [ -z "$extdrivelabel" ]; then
    extdrivelabel="${selecteddrivepath##*/}"
  fi

  resolveiocmonroot
  mkdir -m 755 -p "$iocmonroot/feeds/meta" "$iocmonroot/state"
  [ "$logfilepath" != "$jffslogfile" ] && relocatelogfile "$iocmonroot/state/iocmon.log"
  saveconfig

  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: External drive selected: label=$extdrivelabel path=$selecteddrivepath" >> "$logfile"

  echo ""
  echo ""
  echo -e "${CGreen}IOCMON will use: $iocmonroot${CClear}"
  # echo ""
  # read -rsp $'Press any key to continue...\n' -n1 key
  return 0
}

# -------------------------------------------------------------------------------------------------------------------------
# checkdrivealive re-resolves iocmonroot and verifies it's still mounted every main-loop cycle.

checkdrivealive()
{
  resolveiocmonroot

  if [ -z "$extdrivelabel" ]; then
    driveavailable=0
    drivestatus="${CYellow}Degraded: JFFS-only (no external drive configured)${CClear}"
    return
  fi

  if [ ! -d "$iocmonroot" ]; then
    driveavailable=0
    drivestatus="${CRed}Drive Missing: label=$extdrivelabel is not mounted${CClear}"
    if [ "$driveunmountedalerted" != "1" ]; then
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - ERROR: Configured external drive (label=$extdrivelabel) is not mounted. Feed/hash operations paused." >> "$logfile"
      driveunmountedalerted=1
    fi
  else
    driveavailable=1
    drivestatus="${CGreen}$iocmonroot${CClear}"
    driveunmountedalerted=0
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# resolvelogfile points $logfile at $logfilepath, using JFFS while that folder is missing and merging those lines back after

resolvelogfile()
{
  if [ -z "$logfilepath" ] || [ "$logfilepath" = "$jffslogfile" ]; then
    logfile="$jffslogfile"
  elif [ -d "${logfilepath%/*}" ]; then
    logfile="$logfilepath"
    if [ -f "$jffslogfile" ] || [ -f "$jffslogfile.1" ]; then
      logall "$jffslogfile" >> "$logfile" && rm -f "$jffslogfile" && logremoverotated "$jffslogfile"
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Merged activity log lines written to $jffslogfile while $logfilepath was unavailable." >> "$logfile"
    fi
    logfilefallback=0
  else
    logfile="$jffslogfile"
    if [ "$logfilefallback" != "1" ]; then
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: Activity log location $logfilepath is unavailable (drive not mounted?) - logging to $jffslogfile until it returns." >> "$logfile"
      logfilefallback=1
    fi
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# relocatelogfile moves the current activity log's contents to $1 and points logfilepath/logfile there (caller saves config)

relocatelogfile()
{
  local newpath="$1" oldpath="$logfile" i="$logkeep"

  if [ "$newpath" != "$oldpath" ]; then
    mkdir -m 755 -p "${newpath%/*}" || return 1
    while [ "$i" -ge 1 ]; do
      if [ -f "$oldpath.$i" ]; then
        cat "$oldpath.$i" >> "$newpath.$i" || return 1
        rm -f "$oldpath.$i"
      fi
      i=$((i - 1))
    done
    if [ -f "$oldpath" ]; then
      cat "$oldpath" >> "$newpath" || return 1
      rm -f "$oldpath"
    fi
  fi
  logfilepath="$newpath"
  logfile="$newpath"
  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Activity log location set to $newpath (moved from $oldpath)." >> "$logfile"
  return 0
}

# -------------------------------------------------------------------------------------------------------------------------
# initialsetup runs the drive picker, an optional import, the settings and web interface questions, then saves the config.

initialsetup()
{
  mkdir -m 755 -p "$addonsdir"

  if ! selectextdrive; then
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - ERROR: Initial setup did not complete - external drive selection was cancelled." >> "$logfile"
    logoNMexit
    exit 1
  fi

  sleep 2
  local importfile setupall=0
  setupbanner "2. Import IOCMON Settings" \
    "If you exported your settings from a previous IOCMON installation (Configuration Menu item 7), you can import that .ioc file now." \
    "An import supplies every setting, so only the web interface question follows it. Otherwise setup continues with its other questions."
  echo -e "Would you like to import an existing IOCMON Settings Export (.ioc) file?"
  if promptyn "[y/n]: "; then
    echo ""
    echo ""
    read -p "Full path to the .ioc file to import: " importfile
    if [ -n "$importfile" ] && [ -f "$importfile" ] && grep -q '^timerloop=' "$importfile" && grep -q '^fswatchdirs=' "$importfile"; then
      applyimportedconfig "$importfile"
      echo ""
      echo -e "${CGreen}Settings imported successfully.${CClear}"
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: IOCMON initial config created by importing $importfile." >> "$logfile"
      sleep 2
      setupwebui 3
      return
    fi
    echo ""
    echo -e "${CRed}ERROR: $importfile not found or not a valid IOCMON export - continuing with default setup.${CClear}"
    sleep 3
  fi

  fswatchdirs="/jffs/scripts /jffs/configs /jffs/addons /jffs/.ssh /tmp/mnt/$extdrivelabel"
  alertlevel="critical"
  setupprofile && setupall=1
  saveconfig

  if [ "$setupall" -eq 1 ]; then
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: IOCMON initial config created with all detection features enabled." >> "$logfile"
    setupdnswatch
  else
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: IOCMON initial config created with defaults." >> "$logfile"
  fi

  setupapikeyinfo
  setupwebui 5
}

# -------------------------------------------------------------------------------------------------------------------------
# setupbanner clears the screen and draws a setup step's banner, titled $1, with each later argument as one description line

setupbanner()
{
  local title="$1" line
  shift
  clear
  echo -en "${InvGreen} ${InvDkGray}${CWhite} "; padright "$title" 136; echo -e "${CClear}"
  echo -e "${InvGreen} ${CClear}"
  for line in "$@"; do
    echo -e "${InvGreen} ${CClear} ${line}${CClear}"
  done
  echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
  echo ""
}

# -------------------------------------------------------------------------------------------------------------------------
# setupprofile asks for the default settings or all functionality, returning 0 and switching the extra features on for the latter

setupprofile()
{
  local answer
  setupbanner "3. IOCMON Detection Settings" \
    "Choose how much IOCMON watches and alerts on from the start. Any of these can be changed later under Configuration Menu ${advsettingsmenunum}." \
    "" \
    "${CGreen}1${CClear} = Default settings (recommended): only Critical alerts raise the banner and an email, and the detections most likely to" \
    "    cause noise stay off." \
    "${CGreen}2${CClear} = Enable all: every alert raises the banner and an email, and DNS watch, the DNS tunneling heuristic, permission-change watch and" \
    "    quarantine of files matching a malware hash are switched on. DNS watch turns on dnsmasq query logging and restarts dnsmasq."
  echo -e "Would you like to proceed with the default settings (recommended), or enable all possible functionality now?"
  read -p "Please select? (1-2, Enter=1): " answer
  [ "$answer" = "2" ] || return 1
  alertlevel="all"
  enablednswatch=1
  enablednstunnel=1
  enablepermwatch=1
  enablequarantine=1
  return 0
}

# -------------------------------------------------------------------------------------------------------------------------
# setupdnswatch turns on the query source DNS watch reads, during setup's enable-all choice

setupdnswatch()
{
  echo ""
  if dnsusesagh; then
    echo -e "AdGuard Home answers DNS on this router, so DNS watch reads its query log through its API. Add the AdGuard Home login under"
    echo -e "Configuration Menu ${advsettingsmenunum}.2, item 12."
  else
    enablednsquerylogging
  fi
  sleep 3
}

# -------------------------------------------------------------------------------------------------------------------------
# setupapikeyinfo explains which optional services need an API key and where to enter it, then waits for a key press

setupapikeyinfo()
{
  setupbanner "4. Optional API Keys" \
    "Some optional IOCMON services need a free API key: the URLhaus and ThreatFox feeds (one abuse.ch Auth-Key from ${CGreen}auth.abuse.ch${CClear} works" \
    "for both), the Q-Feeds feed (a token from ${CGreen}tip.qfeeds.com${CClear}) and AbuseIPDB reputation checks (a key from ${CGreen}abuseipdb.com${CClear}). To use one, sign" \
    "up on its site, create an API key, then open Configuration Menu item 2 (Feed Sources, Reputation, API Keys and Lookups), switch the" \
    "service on and paste the key into its key field. Until then, IOCMON uses its keyless feeds: Feodo Tracker, Spamhaus DROP/EDROP" \
    "and NetAPI."
  read -rsp $'Press any key to continue...\n' -n1 key
}

# -------------------------------------------------------------------------------------------------------------------------
# setupwebui offers to install the web interface tab during setup, leaving it off with a pointer to 10.6 if that fails

setupwebui()
{
  setupbanner "$1. IOCMON Web Interface" \
    "The web interface adds an IOCMON tab under the Addons menu of the router's web interface, showing the same status, feeds and logs as" \
    "this script, with buttons for common actions. It needs a web interface login to view, and publishes no API keys, passwords or settings."
  echo -e "Would you like to enable the IOCMON Web Interface?"
  if ! promptyn "[y/n]: "; then
    echo ""
    return
  fi
  echo ""
  if ! webuienable; then
    echo -e "You can try again later under Configuration Menu ${advsettingsmenunum}.6, item 9."
  fi
  sleep 3
}

# -------------------------------------------------------------------------------------------------------------------------
# vsetup is the top-level Configuration Menu: a status summary plus hotkeys into each submenu.

vsetup()
{
  while true; do
    [ "$exitallmenus" -eq 1 ] && break
    clear
    resolveiocmonroot
    echo -e "${InvGreen} ${InvDkGray}${CWhite} IOCMON Configuration Menu                                                                                                               ${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Please choose from the various options below, which allow you to configure IOCMON's storage, feed sources, and detection settings, or${CClear}"
    echo -e "${InvGreen} ${CClear} perform maintenance actions.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${InvDkGray}${CWhite} [IOCMON Operations]                                                                                                                     ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 1)${CClear} : Select Feed Storage Location (Ext. Drive)${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 2)${CClear} : Select Feed Sources, Reputation, API Keys and Lookups${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 3)${CClear} : Force IoC Threat Feed Refresh${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 4)${CClear} : Force Filesystem-Integrity Scan${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 5)${CClear} : OTX AlienVault Threat Report${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${InvDkGray}${CWhite} [Setup + Configuration]                                                                                                                 ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 6)${CClear} : Reset IOCMON back to Default Settings${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 7)${CClear} : Import/Export IOCMON Settings${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 8)${CClear} : Update IOCMON to Latest Version${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 9)${CClear} : Optional Entware Components${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}"; printf '(%2d)' "$advsettingsmenunum"; echo -e "${CClear} : Advanced Settings${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(11)${CClear} : Uninstall IOCMON${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}  | ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( e)${CClear} : Exit${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (1-11, e=Exit): " selsetup
    case "$selsetup" in
      1) selectextdrive ;;
      2) vfeedsources ;;
      3) forcefeeds ;;
      4) forcefsintegrity ;;
      5) votxreport ;;
      6) vresetdefaults ;;
      7) vimportexport ;;
      8) vupdate ;;
      9) ventwarecomponents ;;
      "$advsettingsmenunum") vadvanced ;;
      11) vuninstall ;;
      [Ee]) break ;;
      [Ee]!) exitallmenus=1; break ;;
      *) ;;
    esac
  done

  exitallmenus=0
  if [ "$timerpaused" -eq 1 ]; then renderdashboard; else timer=$timerloop; fi
}

# -------------------------------------------------------------------------------------------------------------------------
# validateint checks that $1 is a non-negative integer >= $2 (the minimum allowed value)

validateint()
{
  echo "$1" | grep -qE '^[0-9]+$' && [ "$1" -ge "$2" ]
}

# -------------------------------------------------------------------------------------------------------------------------
# togglesetting flips a named 0/1 config variable and saves

togglesetting()
{
  local varname="$1" curval
  eval "curval=\$$varname"
  if [ "$curval" -eq 1 ]; then eval "$varname=0"; else eval "$varname=1"; fi
  saveconfig
}

# -------------------------------------------------------------------------------------------------------------------------
# validipcidr checks $1 is a well-formed IPv4 address (each octet 0-255), optionally /N with N 0-32.

validipcidr()
{
  local val="$1" ip mask hasslash=0 octet oldifs
  case "$val" in
    */*) hasslash=1; mask="${val#*/}"; ip="${val%%/*}" ;;
    *) ip="$val"; mask="" ;;
  esac
  if [ "$hasslash" -eq 1 ]; then
    case "$mask" in "") return 1 ;; *[!0-9]*) return 1 ;; esac
    [ "$mask" -ge 0 ] && [ "$mask" -le 32 ] || return 1
  fi
  oldifs="$IFS"; IFS=.; set -- $ip; IFS="$oldifs"
  [ "$#" -eq 4 ] || return 1
  for octet in "$1" "$2" "$3" "$4"; do
    case "$octet" in "") return 1 ;; *[!0-9]*) return 1 ;; esac
    [ "$octet" -ge 0 ] && [ "$octet" -le 255 ] || return 1
  done
  return 0
}

# -------------------------------------------------------------------------------------------------------------------------
# validdatestr checks $1 is a plain YYYY-MM-DD date string (no calendar-day existence check beyond the field widths)

validdatestr()
{
  echo "$1" | grep -qE '^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$'
}

# -------------------------------------------------------------------------------------------------------------------------
# validdomainentry accepts one domain name made of letters, digits, dots and hyphens, with a dot and no leading/trailing dot or hyphen

validdomainentry()
{
  echo "$1" | grep -qE '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$' && case "$1" in *.*) ! echo "$1" | grep -q '\.\.' ;; *) false ;; esac
}

# -------------------------------------------------------------------------------------------------------------------------
# veditlist is a numbered add/edit/delete editor for a space-separated list stored in $1

veditlist()
{
  local varname="$1" title="$2" hint="${3:-absolute path}" desc1="$4" desc2="$5" list count entry idx sel newval delnum newlist overlapmsg

  while true; do
    [ "$exitallmenus" -eq 1 ] && break
    eval "list=\"\$$varname\""
    clear
    echo -en "${InvGreen} ${InvDkGray}${CWhite} "; padright "$title" 136; echo -e "${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Choose an entry number to edit it, (a) to add a new entry, or (d) to delete one.${CClear}"
    [ -n "$desc1" ] && echo -e "${InvGreen} ${CClear} ${desc1}${CClear}"
    [ -n "$desc2" ] && echo -e "${InvGreen} ${CClear} ${desc2}${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"

    count=0
    set -- $list
    if [ "$#" -eq 0 ]; then
      echo -e "${InvGreen} ${CClear} ${CDkGray}(no entries configured)${CClear}"
    else
      for entry in "$@"; do
        count=$((count+1))
        echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}($count)${CClear} : ${CGreen}${entry}${CClear}"
      done
    fi
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite} | ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(a)${CClear} : Add a new entry${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(d)${CClear} : Delete an entry${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(e)${CClear} : Return to Advanced Settings${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (1-$count, a=Add, d=Delete, e=Exit): " sel

    case "$sel" in
      [Aa])
        read -p "New entry ($hint): " newval
        if [ -n "$newval" ]; then
          if [ "$varname" = "fswatchdirs" ]; then
            overlapmsg="$(fswatchdiroverlap "$newval")"
            if [ -n "$overlapmsg" ]; then
              echo ""
              echo -e "${CYellow}${overlapmsg}${CClear}"
              echo -e "Add it anyway?"
              promptyn "[y/n]: " || continue
            fi
          elif [ "$varname" = "ipexceptions" ] && ! validipcidr "$newval"; then
            echo ""
            echo -e "${CRed}Invalid entry - expected a single IP (e.g. 204.44.63.22) or a CIDR range (e.g. 204.44.0.0/16, prefix 0-32).${CClear}"
            sleep 3
            continue
          elif [ "$varname" = "dnssharedhosts" ] && ! validdomainentry "$newval"; then
            echo ""
            echo -e "${CRed}Invalid entry - expected one domain name, e.g. github.com (letters, digits, dots and hyphens only).${CClear}"
            sleep 3
            continue
          fi
          [ "$varname" = "dnssharedhosts" ] && newval="$(echo "$newval" | tr 'A-Z' 'a-z')"
          eval "$varname=\"\${$varname:+\$$varname }\$newval\""
          saveconfig
        fi
        ;;
      [Dd])
        [ "$count" -eq 0 ] && continue
        read -p "Delete which entry number? (1-$count, blank to cancel): " delnum
        if echo "$delnum" | grep -qE '^[0-9]+$' && [ "$delnum" -ge 1 ] && [ "$delnum" -le "$count" ]; then
          set -- $list
          idx=0
          newlist=""
          for entry in "$@"; do
            idx=$((idx+1))
            [ "$idx" -eq "$delnum" ] && continue
            newlist="${newlist:+$newlist }$entry"
          done
          eval "$varname=\"\$newlist\""
          saveconfig
        fi
        ;;
      [Ee]) break ;;
      [Ee]!) exitallmenus=1; break ;;
      *)
        if echo "$sel" | grep -qE '^[0-9]+$' && [ "$sel" -ge 1 ] && [ "$sel" -le "$count" ]; then
          set -- $list
          eval "entry=\"\${$sel}\""
          echo -e "Current: ${CGreen}${entry}${CClear}"
          read -p "New value (blank to keep current): " newval
          if [ -n "$newval" ]; then
            if [ "$varname" = "ipexceptions" ] && ! validipcidr "$newval"; then
              echo ""
              echo -e "${CRed}Invalid entry - expected a single IP (e.g. 204.44.63.22) or a CIDR range (e.g. 204.44.0.0/16, prefix 0-32).${CClear}"
              sleep 3
              continue
            elif [ "$varname" = "dnssharedhosts" ] && ! validdomainentry "$newval"; then
              echo ""
              echo -e "${CRed}Invalid entry - expected one domain name, e.g. github.com (letters, digits, dots and hyphens only).${CClear}"
              sleep 3
              continue
            fi
            [ "$varname" = "dnssharedhosts" ] && newval="$(echo "$newval" | tr 'A-Z' 'a-z')"
            set -- $list
            idx=0
            newlist=""
            for entry in "$@"; do
              idx=$((idx+1))
              if [ "$idx" -eq "$sel" ]; then newlist="${newlist:+$newlist }$newval"; else newlist="${newlist:+$newlist }$entry"; fi
            done
            eval "$varname=\"\$newlist\""
            saveconfig
          fi
        fi
        ;;
    esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# listlivecronjobs prints every cron entry checkcronbaseline/checkentwarecron currently look at

listlivecronjobs()
{
  local srcfiles="" f
  crul && [ -n "$cruout" ] && printf '%s\n' "$cruout"

  [ -f /opt/etc/crontab ] && srcfiles="/opt/etc/crontab"
  for f in /opt/var/spool/cron/crontabs/*; do
    [ -f "$f" ] && srcfiles="$srcfiles $f"
  done
  [ -n "$srcfiles" ] && cat $srcfiles 2>/dev/null | grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$'
}

# -------------------------------------------------------------------------------------------------------------------------
# vcronexceptions manages $cronexceptions

vcronexceptions()
{
  local count entry idx sel delnum newlist

  while true; do
    [ "$exitallmenus" -eq 1 ] && break
    clear
    echo -en "${InvGreen} ${InvDkGray}${CWhite} "; padright "${advsettingsmenunum}.4.13 Cron Exceptions" 136; echo -e "${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Cron entries listed below never raise an alert, even when checkcronbaseline/checkentwarecron see them disappear and reappear - for${CClear}"
    echo -e "${InvGreen} ${CClear} entries a script/addon manages on its own schedule.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"

    count=0
    if [ -z "$cronexceptions" ]; then
      echo -e "${InvGreen} ${CClear} ${CDkGray}(no exceptions configured)${CClear}"
    else
      while IFS= read -r entry; do
        count=$((count+1))
        [ "${#entry}" -gt 120 ] && entry="$(printf '%.119s' "$entry")>"
        echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}($count)${CClear} : ${CGreen}${entry}${CClear}"
      done <<EOF
$cronexceptions
EOF
    fi
    count="$(printf '%s\n' "$cronexceptions" | grep -c '.')"
    [ -z "$cronexceptions" ] && count=0

    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite} | ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(a)${CClear} : Add an exception (pick from current cron jobs)${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(b)${CClear} : Add all current cron jobs as exceptions${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(c)${CClear} : Clear all exceptions from the list${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(d)${CClear} : Delete an exception${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(e)${CClear} : Return to Advanced Settings${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (a=Add, b=Add All, c=Clear All, d=Delete, e=Exit): " sel

    case "$sel" in
      [Aa])
        clear
        echo -e "${CGreen}[Select a Cron Entry to Except]${CClear}"
        echo ""

        local alljobs
        alljobs="$(listlivecronjobs)"
        if [ -z "$alljobs" ]; then
          echo -e "${CRed}No cron entries were found to choose from.${CClear}"
          echo ""
          read -rsp $'Press any key to continue...\n' -n1 key
          continue
        fi

        idx=0
        printf '%s\n' "$alljobs" | while IFS= read -r entry; do
          idx=$((idx+1))
          echo -e "  ${InvDkGray}${CWhite}($idx)${CClear} : $entry"
        done

        echo ""
        local picknum
        read -p "Select entry number to except (blank to cancel): " picknum
        if [ -n "$picknum" ] && echo "$picknum" | grep -qE '^[0-9]+$'; then
          entry="$(printf '%s\n' "$alljobs" | sed -n "${picknum}p")"
          if [ -z "$entry" ]; then
            echo -e "${CRed}Invalid selection.${CClear}"
            sleep 1
          elif incronexceptionlist "$entry"; then
            echo -e "${CYellow}That entry is already excepted.${CClear}"
            sleep 1
          else
            if [ -z "$cronexceptions" ]; then
              cronexceptions="$entry"
            else
              cronexceptions="$cronexceptions
$entry"
            fi
            saveconfig
            echo ""
            echo -e "${CGreen}Exception added.${CClear}"
            sleep 1
          fi
        fi
        ;;
      [Bb])
        local addall addedcount=0
        addall="$(listlivecronjobs)"
        echo ""
        if [ -z "$addall" ]; then
          echo -e "${CRed}No cron entries were found to add.${CClear}"
        else
          while IFS= read -r entry; do
            [ -z "$entry" ] && continue
            incronexceptionlist "$entry" && continue
            if [ -z "$cronexceptions" ]; then cronexceptions="$entry"; else cronexceptions="$cronexceptions
$entry"; fi
            addedcount=$((addedcount+1))
          done <<EOF
$addall
EOF
          if [ "$addedcount" -gt 0 ]; then
            saveconfig
            echo -e "${CGreen}Added $addedcount cron entr$([ "$addedcount" -eq 1 ] && echo y || echo ies) as exceptions.${CClear}"
          else
            echo -e "${CYellow}Every current cron entry is already excepted.${CClear}"
          fi
        fi
        sleep 2
        ;;
      [Cc])
        [ "$count" -eq 0 ] && continue
        echo ""
        if promptyn "Remove all $count exception(s) from the list? [y/n]: "; then
          cronexceptions=""
          saveconfig
          echo ""
          echo ""
          echo -e "${CGreen}All cron exceptions cleared.${CClear}"
          sleep 2
        fi
        ;;
      [Dd])
        [ "$count" -eq 0 ] && continue
        read -p "Delete which entry number? (1-$count, blank to cancel): " delnum
        if echo "$delnum" | grep -qE '^[0-9]+$' && [ "$delnum" -ge 1 ] && [ "$delnum" -le "$count" ]; then
          idx=0
          newlist=""
          while IFS= read -r entry; do
            idx=$((idx+1))
            [ "$idx" -eq "$delnum" ] && continue
            if [ -z "$newlist" ]; then newlist="$entry"; else newlist="$newlist
$entry"; fi
          done <<EOF
$cronexceptions
EOF
          cronexceptions="$newlist"
          saveconfig
        fi
        ;;
      [Ee]) break ;;
      [Ee]!) exitallmenus=1; break ;;
      *) ;;
    esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# vdnsexceptions is a dedicated 2-column/paginated/find/edit editor for dnsexceptions (the one list expected to grow largest)

vdnsexceptions()
{
  local list count page=1 perpage=60 leftwidth=70 totalbudget=136 rightmax badgewidth prefixlen leftbudget rightbudget entrybudget
  local totalpages pagestart r leftidx rightidx leftentry rightentry leftdisp rightdisp leftbadge rightbadge leftplain leftpad rightout
  local sel pendingeditnum newval idx entry newlist delnum pattern fcount hp hpad editnum faction fdel

  while true; do
    [ "$exitallmenus" -eq 1 ] && break
    pendingeditnum=""
    list="$dnsexceptions"
    set -- $list
    count=$#
    badgewidth=${#count}
    [ "$badgewidth" -lt 1 ] && badgewidth=1
    totalpages=$(( (count + perpage - 1) / perpage ))
    [ "$totalpages" -lt 1 ] && totalpages=1
    [ "$page" -gt "$totalpages" ] && page=$totalpages
    [ "$page" -lt 1 ] && page=1

    prefixlen=$((badgewidth + 5))
    rightmax=$((totalbudget - leftwidth))
    leftbudget=$((leftwidth - prefixlen - 3))
    rightbudget=$((rightmax - prefixlen))
    entrybudget=$leftbudget
    [ "$rightbudget" -lt "$entrybudget" ] && entrybudget=$rightbudget
    [ "$entrybudget" -lt 10 ] && entrybudget=10

    clear
    echo -en "${InvGreen} ${InvDkGray}${CWhite} "; padright "${advsettingsmenunum}.2.2 DNS Domain Exceptions" 136; echo -e "${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Choose an entry number to edit it, (a) to add a new entry, (d) to delete one, (t) to edit${CClear}"
    echo -e "${InvGreen} ${CClear} an entry, or (f) to find an entry. Page ${CGreen}${page}${CClear}/${CGreen}${totalpages}${CClear}, ${CGreen}${count}${CClear} entries total.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"

    if [ "$count" -eq 0 ]; then
      echo -e "${InvGreen} ${CClear} ${CDkGray}(no entries configured)${CClear}"
    else
      pagestart=$(( (page-1) * perpage ))
      r=1
      while [ "$r" -le 30 ]; do
        leftidx=$((pagestart + r))
        [ "$leftidx" -gt "$count" ] && break
        eval "leftentry=\"\${$leftidx}\""
        leftdisp="$leftentry"
        [ "${#leftdisp}" -gt "$entrybudget" ] && leftdisp="$(printf '%.*s' "$((entrybudget-1))" "$leftdisp")>"
        leftbadge="$(printf "(%${badgewidth}d)" "$leftidx")"
        leftplain="${leftbadge} : ${leftdisp}"
        leftpad=$((leftwidth - ${#leftplain}))
        [ "$leftpad" -lt 1 ] && leftpad=1

        rightidx=$((leftidx + 30))
        rightout=""
        if [ "$rightidx" -le "$count" ]; then
          eval "rightentry=\"\${$rightidx}\""
          rightdisp="$rightentry"
          [ "${#rightdisp}" -gt "$entrybudget" ] && rightdisp="$(printf '%.*s' "$((entrybudget-1))" "$rightdisp")>"
          rightbadge="$(printf "(%${badgewidth}d)" "$rightidx")"
          rightout="${InvDkGray}${CWhite}${rightbadge}${CClear} : ${CGreen}${rightdisp}${CClear}"
        fi

        echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}${leftbadge}${CClear} : ${CGreen}${leftdisp}${CClear}$(printf '%*s' "$leftpad" '')${rightout}"
        r=$((r+1))
      done
    fi

    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite} | ${CClear}"
    hp="(a) : Add a new entry"; hpad=$((leftwidth - ${#hp})); [ "$hpad" -lt 1 ] && hpad=1
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(a)${CClear} : Add a new entry$(printf '%*s' "$hpad" '')${InvDkGray}${CWhite}(n)${CClear} : Next page${CClear}"
    hp="(d) : Delete an entry"; hpad=$((leftwidth - ${#hp})); [ "$hpad" -lt 1 ] && hpad=1
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(d)${CClear} : Delete an entry$(printf '%*s' "$hpad" '')${InvDkGray}${CWhite}(p)${CClear} : Previous page${CClear}"
    hp="(f) : Find an entry"; hpad=$((leftwidth - ${#hp})); [ "$hpad" -lt 1 ] && hpad=1
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(f)${CClear} : Find an entry$(printf '%*s' "$hpad" '')${InvDkGray}${CWhite}(e)${CClear} : Return to Advanced Settings${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(t)${CClear} : Edit an entry${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (1-$count, a=Add, d=Delete, f=Find, t=Edit, n=Next, p=Previous, e=Exit): " sel

    case "$sel" in
      [Aa])
        read -p "New domain name entry: " newval
        if [ -n "$newval" ]; then
          dnsexceptions="${dnsexceptions:+$dnsexceptions }$newval"
          saveconfig
          set -- $dnsexceptions
          page=$(( ($# + perpage - 1) / perpage ))
          [ "$page" -lt 1 ] && page=1
        fi
        ;;
      [Dd])
        [ "$count" -eq 0 ] && continue
        read -p "Delete which entry number? (1-$count, blank to cancel): " delnum
        if echo "$delnum" | grep -qE '^[0-9]+$' && [ "$delnum" -ge 1 ] && [ "$delnum" -le "$count" ]; then
          set -- $list
          idx=0; newlist=""
          for entry in "$@"; do
            idx=$((idx+1))
            [ "$idx" -eq "$delnum" ] && continue
            newlist="${newlist:+$newlist }$entry"
          done
          dnsexceptions="$newlist"
          saveconfig
        fi
        ;;
      [Ff])
        read -p "Enter a search term (wildcards * ? allowed, blank to cancel): " pattern
        if [ -n "$pattern" ]; then
          case "$pattern" in
            *'*'*|*'?'*) ;;
            *) pattern="*${pattern}*" ;;
          esac
          clear
          echo -e "${CGreen}[Find Results: \"$pattern\"]${CClear}"
          echo ""
          set -- $list
          idx=0; fcount=0
          for entry in "$@"; do
            idx=$((idx+1))
            case "$entry" in
              $pattern)
                fcount=$((fcount+1))
                echo -e "  ${InvDkGray}${CWhite}(${idx})${CClear} : ${CGreen}${entry}${CClear}"
                ;;
            esac
          done
          echo ""
          if [ "$fcount" -eq 0 ]; then
            echo -e "${CYellow}No entries matched.${CClear}"
            echo ""
            read -rsp $'Press any key to continue...\n' -n1 key
          else
            echo -e "Found ${CGreen}${fcount}${CClear} matching entr$([ "$fcount" -eq 1 ] && echo "y" || echo "ies")."
            echo ""
            read -p "Enter an entry number to edit, (d) to delete one, or blank to return: " faction
            case "$faction" in
              "") ;;
              [Dd])
                read -p "Delete which entry number? (blank to cancel): " fdel
                if echo "$fdel" | grep -qE '^[0-9]+$' && [ "$fdel" -ge 1 ] && [ "$fdel" -le "$count" ]; then
                  set -- $list
                  idx=0; newlist=""
                  for entry in "$@"; do
                    idx=$((idx+1))
                    [ "$idx" -eq "$fdel" ] && continue
                    newlist="${newlist:+$newlist }$entry"
                  done
                  dnsexceptions="$newlist"
                  saveconfig
                fi
                ;;
              *)
                if echo "$faction" | grep -qE '^[0-9]+$' && [ "$faction" -ge 1 ] && [ "$faction" -le "$count" ]; then
                  pendingeditnum="$faction"
                fi
                ;;
            esac
          fi
        fi
        ;;
      [Tt])
        read -p "Edit which entry number? (1-$count, blank to cancel): " editnum
        if echo "$editnum" | grep -qE '^[0-9]+$' && [ "$editnum" -ge 1 ] && [ "$editnum" -le "$count" ]; then
          pendingeditnum="$editnum"
        fi
        ;;
      [Nn]) [ "$page" -lt "$totalpages" ] && page=$((page+1)) ;;
      [Pp]) [ "$page" -gt 1 ] && page=$((page-1)) ;;
      [Ee]) break ;;
      [Ee]!) exitallmenus=1; break ;;
      *)
        if echo "$sel" | grep -qE '^[0-9]+$' && [ "$sel" -ge 1 ] && [ "$sel" -le "$count" ]; then
          pendingeditnum="$sel"
        fi
        ;;
    esac

    if [ -n "$pendingeditnum" ]; then
      set -- $list
      eval "entry=\"\${$pendingeditnum}\""
      echo ""
      echo -e "Current: ${CGreen}${entry}${CClear}"
      read -p "New value (blank to keep current): " newval
      if [ -n "$newval" ]; then
        set -- $list
        idx=0; newlist=""
        for entry in "$@"; do
          idx=$((idx+1))
          if [ "$idx" -eq "$pendingeditnum" ]; then newlist="${newlist:+$newlist }$newval"; else newlist="${newlist:+$newlist }$entry"; fi
        done
        dnsexceptions="$newlist"
        saveconfig
      fi
    fi
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# vadvanced is the top-level Advanced Settings menu

vadvanced()
{
  while true; do
    [ "$exitallmenus" -eq 1 ] && break
    clear
    echo -en "${InvGreen} ${InvDkGray}${CWhite} "; padright "${advsettingsmenunum}. Advanced Settings" 136; echo -e "${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Please choose from the various options below, which allow you to modify certain customizable parameters that affect the operation of${CClear}"
    echo -e "${InvGreen} ${CClear} this script.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(1)${CClear} : Alerting & Notifications${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(2)${CClear} : DNS Watch & Tunneling Detection${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(3)${CClear} : Brute-Force Login Detection${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(4)${CClear} : Filesystem Integrity & Cron Watch${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(5)${CClear} : Network & System Watches${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(6)${CClear} : General / Script Behavior${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite} | ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(e)${CClear} : Exit${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (1-6, e=Exit): " seladv
    case "$seladv" in
      1) vadvancedalerting ;;
      2) vadvanceddns ;;
      3) vadvancedbruteforce ;;
      4) vadvancedfilesystem ;;
      5) vadvancednetwork ;;
      6) vadvancedgeneral ;;
      [Ee]) break ;;
      [Ee]!) exitallmenus=1; break ;;
      *) ;;
    esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# vadvancedalerting: AMTM email dispatch settings.

vadvancedalerting()
{
  while true; do
    [ "$exitallmenus" -eq 1 ] && break
    clear
    echo -en "${InvGreen} ${InvDkGray}${CWhite} "; padright "${advsettingsmenunum}.1 Advanced Settings - Alerting & Notifications" 136; echo -e "${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Controls whether/how often IOCMON emails you, where the SECURITY ALERT banner appears on screen, and which alerts raise it. Every alert${CClear}"
    echo -e "${InvGreen} ${CClear} has a severity, shown as its colour in the IoC log: ${CRed}Critical${CClear} (feed-matched connections, file hash matches, brute-force logins, file,${CClear}"
    echo -e "${InvGreen} ${CClear} cron, firewall and NVRAM setting changes), ${CYellow}Warning${CClear} (DNS feed matches, firmware-rewritten WAN DNS values) and ${CDkGray}Info${CClear} (DNS tunneling${CClear}"
    echo -e "${InvGreen} ${CClear} hints and DNS matches on shared-hosting domains). With the Critical Only level, only Critical alerts raise the banner and send email;${CClear}"
    echo -e "${InvGreen} ${CClear} the others are still logged. A DNS match becomes Critical when ThreatFox lists it as botnet C2, or AbuseIPDB scores its IP at or${CClear}"
    echo -e "${InvGreen} ${CClear} above item 5.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(1)${CClear} : "; padright "Send an AMTM email whenever a real IOC detection fires" 68; echo -e ": $(booleantoyesno "$enablealertemail")"
    menurow "(2)" "Maximum alert emails per hour (0 = unlimited)" "${CGreen}$ratelimit${CClear}" 68 "$enablealertemail"
    if [ "$alertbanneratbottom" -eq 1 ]; then bannerposdisp="Bottom"; else bannerposdisp="Top"; fi
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(3)${CClear} : "; padright "SECURITY ALERT banner screen position (Top/Bottom)" 68; echo -e ": ${CGreen}${bannerposdisp}${CClear}"
    migratealertlevel
    if [ "$alertlevel" = "critical" ]; then alertleveldisp="Critical Only"; else alertleveldisp="All Alerts"; fi
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(4)${CClear} : "; padright "Alert level for the banner and email (All Alerts/Critical Only)" 68; echo -e ": ${CGreen}${alertleveldisp}${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(5)${CClear} : "; padright "AbuseIPDB score that makes a DNS match Critical (1-100)" 68; echo -e ": ${CGreen}${dnsescalatescore}%${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite} | ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(e)${CClear} : Return to Advanced Settings${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (1-5, e=Exit): " sel
    case "$sel" in
      1) togglesetting enablealertemail ;;
      2) [ "$enablealertemail" -eq 1 ] && { echo -e "Current: ${CGreen}${ratelimit}${CClear}"
         read -p "New email rate limit, emails/hr (0=unlimited, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 0 && ratelimit="$val" && saveconfig; }; } ;;
      3) togglesetting alertbanneratbottom ;;
      4) if [ "$alertlevel" = "critical" ]; then alertlevel="all"; else alertlevel="critical"; fi; saveconfig ;;
      5) echo ""; echo -e "Current: ${CGreen}${dnsescalatescore}%${CClear}"
         read -p "New AbuseIPDB score, 1-100 (blank to keep current): " val
         [ -n "$val" ] && validateint "$val" 1 && [ "$val" -le 100 ] && { dnsescalatescore="$val"; saveconfig; } ;;
      [Ee]) break ;;
      [Ee]!) exitallmenus=1; break ;;
      *) ;;
    esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# vadvanceddns: feed-based DNS matching (checkdns) plus the behavioral DNS-tunneling/exfiltration heuristic.

vadvanceddns()
{
  while true; do
    [ "$exitallmenus" -eq 1 ] && break
    clear
    echo -en "${InvGreen} ${InvDkGray}${CWhite} "; padright "${advsettingsmenunum}.2 Advanced Settings - DNS Watch & Tunneling Detection" 136; echo -e "${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Controls matching DNS lookups against known-malicious-domain feeds, exceptions to that matching, and the separate behavioral heuristic${CClear}"
    echo -e "${InvGreen} ${CClear} for tunneling/exfiltration. Lookups come from dnsmasq's query log, or from AdGuard Home's query log through its API when AdGuard Home${CClear}"
    echo -e "${InvGreen} ${CClear} answers DNS on this router (item 11). A second AdGuard Home can be a backup (items 14 and 15), read only when the first fails.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    dnswatchdisp="$(booleantoyesno "$enablednswatch")"
    if [ "$enablednswatch" -eq 1 ] && ! dnsusesagh && ! dnsquerylogenabled; then dnswatchdisp="${dnswatchdisp} (awaiting dnsmasq query-log setup)"; fi
    case "$dnssource" in
      adguardhome) dnssrcdisp="${CGreen}AdGuard Home${CClear}" ;;
      dnsmasq) dnssrcdisp="${CGreen}dnsmasq${CClear}" ;;
      *) if dnsusesagh; then dnssrcdisp="${CGreen}auto${CClear} (AdGuard Home detected)"; else dnssrcdisp="${CGreen}auto${CClear} (dnsmasq)"; fi ;;
    esac
    aghon=0; [ "$enablednswatch" -eq 1 ] && dnsusesagh && aghon=1
    if [ "$aghon" -ne 1 ]; then aghdisp="n/a"
    elif ! aghhaslogin; then aghdisp="${CYellow}<none - required for AdGuard Home>${CClear}"
    elif aghstatus >/dev/null; then aghdisp="${CGreen}<set> | <connected>${CClear}"
    else aghdisp="${CYellow}<set> | <not connected>${CClear}"; fi
    if [ -n "$aghurl" ]; then aghurldisp="${CGreen}${aghurl}${CClear}"; else aghurldisp="${CGreen}auto${CClear} ($(aghapiurl))"; fi
    if [ "$aghon" -ne 1 ]; then aghdisp2="n/a"
    elif [ -z "$aghcred2" ]; then aghdisp2="<none>"
    elif [ -z "$aghurl2" ]; then aghdisp2="${CYellow}<set> | <no address>${CClear}"
    elif (aghslot=2; aghstatus >/dev/null); then aghdisp2="${CGreen}<set> | <connected>${CClear}"
    else aghdisp2="${CYellow}<set> | <not connected>${CClear}"; fi
    aghurl2disp="<none>"; [ -n "$aghurl2" ] && aghurl2disp="${CGreen}${aghurl2}${CClear}"
    tunnelon=0; [ "$enablednswatch" -eq 1 ] && [ "$enablednstunnel" -eq 1 ] && tunnelon=1
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 1)${CClear} : "; padright "Watch DNS lookups for known-malicious domains" 68; echo -e ": $dnswatchdisp"
    menurow "( 2)" "DNS domain exceptions (logged, never alerted/emailed)" "${CGreen}$(echo "$dnsexceptions" | wc -w | tr -d ' ')${CClear} configured" 68 "$enablednswatch"
    menurow "( 3)" "Shared-hosting domains (DNS matches logged as Info, not alerted)" "${CGreen}$(echo "$dnssharedhosts" | wc -w | tr -d ' ')${CClear} configured" 68 "$enablednswatch"
    menurow "( 4)" "Watch for DNS-tunneling/exfiltration patterns (behavioral, no feed)" "$(booleantoyesno "$enablednstunnel")" 68 "$enablednswatch"
    menurow "( 5)" "  Distinct subdomains/tick under one domain to flag as tunneling" "${CGreen}$dnstunnelsubthreshold${CClear}" 68 "$tunnelon"
    menurow "( 6)" "  Single query-name length (chars) to flag on its own" "${CGreen}$dnstunnelnamelen${CClear}" 68 "$tunnelon"
    menurow "( 7)" "DNS query log file (for syslog-ng/scribe; blank = auto-detect)" "${CGreen}${dnslogpath:-auto}${CClear}" 68 "$enablednswatch"
    filelogon=0; [ "$enablednswatch" -eq 1 ] && [ "$dnsforcefilelog" -eq 1 ] && filelogon=1
    menurow "( 8)" "Force file-based DNS query detection logging" "$(booleantoyesno "$dnsforcefilelog")" 68 "$enablednswatch"
    menurow "( 9)" "  Rotate that file once it reaches this size (KB)" "${CGreen}$dnsquerylogmaxkb${CClear}" 68 "$filelogon"
    menurow "(10)" "  Rotated generations to keep before deleting the oldest" "${CGreen}$dnsquerylogkeep${CClear}" 68 "$filelogon"
    menurow "(11)" "DNS query source (auto / dnsmasq / AdGuard Home)" "$dnssrcdisp" 68 "$enablednswatch"
    menurow "(12)" "  AdGuard Home API login" "$aghdisp" 68 "$aghon"
    menurow "(13)" "  AdGuard Home API address (auto = read from AdGuardHome.yaml)" "$aghurldisp" 68 "$aghon"
    menurow "(14)" "  Backup AdGuard Home API login (optional)" "$aghdisp2" 68 "$aghon"
    menurow "(15)" "  Backup AdGuard Home API address (optional)" "$aghurl2disp" 68 "$aghon"
    menurow "(16)" "  Also check queries AdGuard Home already blocked" "$(booleantoyesno "$aghincludeblocked")" 68 "$aghon"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}  | ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( e)${CClear} : Return to Advanced Settings${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (1-16, e=Exit): " sel
    case "$sel" in
      1) if [ "$enablednswatch" -eq 1 ]; then
           togglesetting enablednswatch
           if dnsquerylogenabled; then
             echo ""
             disablednsquerylogging
             echo ""
             read -rsp $'Press any key to continue...\n' -n1 key
           fi
         else
           enablednswatch=1
           saveconfig
           if dnsusesagh; then
             echo ""
             echo -e "AdGuard Home answers DNS on this router, so DNS watch reads AdGuard Home's query log through its API."
             echo -e "AdGuard Home: ${CGreen}$(aghstatus)${CClear}"
             echo -e "Set or change the AdGuard Home login with item 12."
             echo ""
             read -rsp $'Press any key to continue...\n' -n1 key
           elif dnsquerylogactiveinetc; then
             echo ""
             echo -e "${CGreen}log-queries is already active in /etc/dnsmasq.conf (likely set by another script) - nothing added to dnsmasq.conf.add, no restart needed.${CClear}"
             echo ""
             read -rsp $'Press any key to continue...\n' -n1 key
           elif ! dnsquerylogenabled; then
             echo ""
             echo -e "DNS watching also needs the router's own dnsmasq query logging turned on - IOCMON can't see queries dnsmasq isn't already logging."
             echo -e "IOCMON already checked and found no other script (e.g. Diversion) has log-queries active in /etc/dnsmasq.conf, so this is safe."
             echo -e "This appends '${CGreen}log-queries${CClear}' to /jffs/configs/dnsmasq.conf.add and restarts dnsmasq so the new logging takes effect right away."
             echo ""
             echo -e "Enable DNS query logging now?"
             if promptyn "[y/n]: "; then
               echo ""
               enablednsquerylogging
             fi
             echo ""
             read -rsp $'Press any key to continue...\n' -n1 key
           fi
         fi
         ;;
      2) [ "$enablednswatch" -eq 1 ] && vdnsexceptions ;;
      3) [ "$enablednswatch" -eq 1 ] && veditlist dnssharedhosts "${advsettingsmenunum}.2.3 Shared-Hosting Domains" "a domain, e.g. github.com - also covers its subdomains" \
           "A DNS feed match on these domains (or their subdomains) is logged as Info: it stays in the IoC log in gray, but never raises the banner" \
           "or sends email in the Critical Only alert level. Malware is sometimes downloaded from these sites, so only list ones you trust." ;;
      4) [ "$enablednswatch" -eq 1 ] && togglesetting enablednstunnel ;;
      5) [ "$tunnelon" -eq 1 ] && { echo -e "Current: ${CGreen}${dnstunnelsubthreshold}${CClear}"
         read -p "New distinct-subdomain threshold (>=1, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 1 && dnstunnelsubthreshold="$val" && saveconfig; }; } ;;
      6) [ "$tunnelon" -eq 1 ] && { echo -e "Current: ${CGreen}${dnstunnelnamelen}${CClear}"
         read -p "New query-name length threshold, chars (>=1, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 1 && dnstunnelnamelen="$val" && saveconfig; }; } ;;
      7) [ "$enablednswatch" -eq 1 ] && { echo ""; echo -e "Current: ${CGreen}${dnslogpath:-auto-detect}${CClear}"; echo ""
         read -p "Full path to the file holding dnsmasq's query lines (blank keeps current, 'auto' clears): " val
         if [ "$val" = "auto" ]; then
           dnslogpath=""; dnslogautotime=0; saveconfig
         elif [ -n "$val" ]; then
           case "$val" in
             /*) [ -f "$val" ] || echo -e "${CYellow}Note: $val does not exist yet - IOCMON will keep auto-detecting until it does.${CClear}"
                 dnslogpath="$val"; dnslogautotime=0; saveconfig ;;
             *) echo -e "${CRed}Please enter an absolute path (starting with /).${CClear}"; sleep 2 ;;
           esac
         fi; } ;;
      8) if [ "$enablednswatch" -eq 1 ]; then
           if [ "$dnsforcefilelog" -eq 1 ]; then
             togglesetting dnsforcefilelog
             echo ""
             disablednsfilelogging
           else
             togglesetting dnsforcefilelog
             echo ""
             enablednsfilelogging
           fi
           echo ""
           read -rsp $'Press any key to continue...\n' -n1 key
         fi
         ;;
      9) [ "$filelogon" -eq 1 ] && { echo -e "Current: ${CGreen}${dnsquerylogmaxkb}${CClear} KB"
         read -p "New rotation size threshold in KB (>=1, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 1 && dnsquerylogmaxkb="$val" && saveconfig; }; } ;;
      10) [ "$filelogon" -eq 1 ] && { echo -e "Current: ${CGreen}${dnsquerylogkeep}${CClear}"
         read -p "New number of rotated generations to keep (>=1, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 1 && dnsquerylogkeep="$val" && saveconfig; }; } ;;
      11) [ "$enablednswatch" -eq 1 ] && { echo ""; echo -e "Current: ${CGreen}${dnssource}${CClear}"; echo ""
          echo -e "  1 : auto         - AdGuard Home's query log when AdGuard Home answers on port 53, otherwise dnsmasq's (default)"
          echo -e "  2 : dnsmasq      - always dnsmasq's query log (log-queries)"
          echo -e "  3 : AdGuard Home - always AdGuard Home's query log, through its API"
          echo ""
          read -p "New DNS query source (1-3, blank to keep current): " val
          case "$val" in
            1) dnssource="auto" ;;
            2) dnssource="dnsmasq" ;;
            3) dnssource="adguardhome" ;;
            "") ;;
            *) echo -e "${CRed}Please enter 1, 2 or 3.${CClear}"; sleep 2; val="" ;;
          esac
          [ -n "$val" ] && { dnslogannounced=""; saveconfig; }; } ;;
      12) [ "$aghon" -eq 1 ] && { echo ""
          echo -e "IOCMON reads AdGuard Home's query log with the same login as AdGuard Home's web UI."
          echo -e "It is stored base64-encoded in ${CGreen}${config}${CClear} (readable by root only) and never passed on a command line."
          echo -e "API address: ${CGreen}$(aghapiurl)${CClear} (change it with item 13)"
          echo ""
          read -p "AdGuard Home username (blank to keep the current login): " aghu
          if [ -n "$aghu" ]; then
            read -rsp "AdGuard Home password: " aghp; echo ""
            aghnew="$(aghencode "$aghu:$aghp")"; aghp=""
            if [ -n "$aghnew" ]; then
              aghcred="$aghnew"; aghnew=""; saveconfig
              aghlog "INFO" "AdGuard Home API login updated."
            else
              echo -e "${CRed}The login could not be encoded with openssl, so it was not saved.${CClear}"
            fi
          fi
          echo ""; echo -e "Testing: $(aghstatus)"; echo ""
          read -rsp $'Press any key to continue...\n' -n1 key; } ;;
      13) [ "$aghon" -eq 1 ] && { echo ""; echo -e "Current: ${CGreen}${aghurl:-auto}${CClear} (in use: $(aghapiurl))"; echo ""
          read -p "AdGuard Home address, e.g. http://192.168.50.1:3000 (blank keeps current, 'auto' reads AdGuardHome.yaml): " val
          if [ "$val" = "auto" ]; then
            aghurl=""
          elif [ -n "$val" ]; then
            val="$(aghnormurl "$val")" && aghurl="$val" || { echo -e "${CRed}Please enter an address like http://192.168.50.1:3000 (letters, digits and . : / _ - only).${CClear}"; sleep 3; val=""; }
          fi
          [ -n "$val" ] && { dnslogannounced=""; saveconfig; echo ""; echo -e "Testing: $(aghstatus)"; echo ""; read -rsp $'Press any key to continue...\n' -n1 key; }; } ;;
      14) [ "$aghon" -eq 1 ] && { echo ""
          echo -e "IOCMON reads a backup AdGuard Home only when the primary (items 12 and 13) fails, and returns to the primary as soon as it answers."
          echo -e "The backup needs its own login and address (item 15). The login is stored the same way as item 12."
          echo ""
          read -p "Backup AdGuard Home username (blank keeps the current login, 'none' removes it): " aghu
          if [ "$aghu" = "none" ]; then
            aghcred2=""; saveconfig
            aghlog "INFO" "Backup AdGuard Home API login removed."
          elif [ -n "$aghu" ]; then
            read -rsp "Backup AdGuard Home password: " aghp; echo ""
            aghnew="$(aghencode "$aghu:$aghp")"; aghp=""
            if [ -n "$aghnew" ]; then
              aghcred2="$aghnew"; aghnew=""; saveconfig
              aghlog "INFO" "Backup AdGuard Home API login updated."
            else
              echo -e "${CRed}The login could not be encoded with openssl, so it was not saved.${CClear}"
            fi
          fi
          [ -n "$aghcred2" ] && { echo ""; echo -e "Testing: $(aghslot=2; aghstatus)"; }
          echo ""
          read -rsp $'Press any key to continue...\n' -n1 key; } ;;
      15) [ "$aghon" -eq 1 ] && { echo ""; echo -e "Current: ${CGreen}${aghurl2:-none}${CClear}"; echo ""
          read -p "Backup AdGuard Home address, e.g. http://192.168.50.3:80 (blank keeps current, 'none' removes it): " val
          if [ "$val" = "none" ]; then
            aghurl2=""
          elif [ "$val" = "auto" ]; then
            echo -e "${CRed}A backup needs its own address: 'auto' only works for an AdGuard Home on this router.${CClear}"; sleep 3; val=""
          elif [ -n "$val" ]; then
            val="$(aghnormurl "$val")" && aghurl2="$val" || { echo -e "${CRed}Please enter an address like http://192.168.50.3:80 (letters, digits and . : / _ - only).${CClear}"; sleep 3; val=""; }
          fi
          [ -n "$val" ] && { saveconfig; [ -n "$aghurl2" ] && { echo ""; echo -e "Testing: $(aghslot=2; aghstatus)"; echo ""; read -rsp $'Press any key to continue...\n' -n1 key; }; }; } ;;
      16) [ "$aghon" -eq 1 ] && togglesetting aghincludeblocked ;;
      [Ee]) break ;;
      [Ee]!) exitallmenus=1; break ;;
      *) ;;
    esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# vadvancedbruteforce: dropbear/httpd login-failure detection - the per-tick burst check and sliding-window sustained check.

vadvancedbruteforce()
{
  while true; do
    [ "$exitallmenus" -eq 1 ] && break
    clear
    echo -en "${InvGreen} ${InvDkGray}${CWhite} "; padright "${advsettingsmenunum}.3 Advanced Settings - Brute-Force Login Detection" 136; echo -e "${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Controls dropbear/httpd login-failure detection: an immediate burst check, and a separate sliding-window check for a slow, sustained${CClear}"
    echo -e "${InvGreen} ${CClear} attempt that stays under it.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(1)${CClear} : "; padright "Watch router logins for brute-force (repeated failed) attempts" 68; echo -e ": $(booleantoyesno "$enableauthwatch")"
    menurow "(2)" "  Same-IP login failures within one check to trigger a burst alert" "${CGreen}$authfailthreshold${CClear}" 68 "$enableauthwatch"
    menurow "(3)" "  Sliding window (hours) for sustained low-and-slow brute-force" "${CGreen}$authslowwindowhrs${CClear}" 68 "$enableauthwatch"
    menurow "(4)" "  Same-IP login failures across that window to trigger an alert" "${CGreen}$authslowthreshold${CClear}" 68 "$enableauthwatch"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite} | ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(e)${CClear} : Return to Advanced Settings${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (1-4, e=Exit): " sel
    case "$sel" in
      1) togglesetting enableauthwatch ;;
      2) [ "$enableauthwatch" -eq 1 ] && { echo -e "Current: ${CGreen}${authfailthreshold}${CClear}"
         read -p "New burst threshold, failures/tick (>=1, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 1 && authfailthreshold="$val" && saveconfig; }; } ;;
      3) [ "$enableauthwatch" -eq 1 ] && { echo -e "Current: ${CGreen}${authslowwindowhrs}${CClear}"
         read -p "New sliding-window size in hours (>=1, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 1 && authslowwindowhrs="$val" && saveconfig; }; } ;;
      4) [ "$enableauthwatch" -eq 1 ] && { echo -e "Current: ${CGreen}${authslowthreshold}${CClear}"
         read -p "New sustained-window threshold, failures/window (>=1, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 1 && authslowthreshold="$val" && saveconfig; }; } ;;
      [Ee]) break ;;
      [Ee]!) exitallmenus=1; break ;;
      *) ;;
    esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# vadvancedfilesystem: the poll-based baseline diff, watched/excluded paths, hashing/quarantine, and the cron-tampering diff.

vadvancedfilesystem()
{
  while true; do
    [ "$exitallmenus" -eq 1 ] && break
    clear
    echo -en "${InvGreen} ${InvDkGray}${CWhite} "; padright "${advsettingsmenunum}.4 Advanced Settings - Filesystem Integrity & Cron Watch" 136; echo -e "${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Controls the periodic filesystem baseline scan, what it watches/skips/hashes, what it does with a confirmed malware-hash match, and${CClear}"
    echo -e "${InvGreen} ${CClear} unexpected new cron entries.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    crondiffon=0; [ "$enablefsintegrity" -eq 1 ] && [ "$enablecrondiff" -eq 1 ] && crondiffon=1
    etccriticalon=0; [ "$enablefsintegrity" -eq 1 ] && [ "$enableetccritical" -eq 1 ] && etccriticalon=1
    menurow "( 1)" "How often to scan watched folders for file changes, in hours" "${CGreen}$fsintegrityhrs${CClear}" 68 "$enablefsintegrity"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 2)${CClear} : "; padright "Watch files/folders below for unexpected changes" 68; echo -e ": $(booleantoyesno "$enablefsintegrity")"
    if [ "$fsmodalertmode" = "hash" ]; then modalertdisp="${CGreen}Upon File Hash Mismatch${CClear}"; else modalertdisp="${CGreen}Upon File Modification${CClear}"; fi
    menurow "( 3)" "Critical-path MOD alert mode (.ssh/startup-scripts/.conf.add)" "$modalertdisp" 68 "$enablefsintegrity"
    menurow "( 4)" "Folders to watch for file changes" "${CGreen}$(echo "$fswatchdirs" | wc -w | tr -d ' ')${CClear} configured" 68 "$enablefsintegrity"
    menurow "( 5)" "  Folder NAMES to exclude by name, not by path" "${CGreen}$(echo "$fswatchexclude" | wc -w | tr -d ' ')${CClear} configured" 68 "$enablefsintegrity"
    menurow "( 6)" "  File extensions excluded from every check (new/mod/del/perm)" "${CGreen}$(echo "$fsexcludeext" | wc -w | tr -d ' ')${CClear} configured" 68 "$enablefsintegrity"
    menurow "( 7)" "  Individual files excluded by absolute path" "${CGreen}$(echo "$fsexcludefiles" | wc -w | tr -d ' ')${CClear} configured" 68 "$enablefsintegrity"
    menurow "( 8)" "Skip hashing files larger than this, in bytes" "${CGreen}$fsmaxhashsize${CClear}" 68 "$enablefsintegrity"
    menurow "( 9)" "Auto-quarantine files matching a known-malware hash (strips +x," "$(booleantoyesno "$enablequarantine")" 68 "$enablefsintegrity"
    echo -e "${InvGreen} ${CClear}         renames to <file>.iocmon-quarantine, never deletes)"
    menurow "(10)" "Alert when a file is DELETED from a critical path" "$(booleantoyesno "$enablefsdeletionwatch")" 68 "$enablefsintegrity"
    menurow "(11)" "Alert when WRITE/EXECUTE permission is added with no changes" "$(booleantoyesno "$enablepermwatch")" 68 "$enablefsintegrity"
    menurow "(12)" "Alert on unexpected new scheduled tasks (cru/Entware cron)" "$(booleantoyesno "$enablecrondiff")" 68 "$enablefsintegrity"
    menurow "(13)" "Cron entries excepted from unexpected-new-entry alerts" "${CGreen}$([ -z "$cronexceptions" ] && echo 0 || printf '%s\n' "$cronexceptions" | wc -l | tr -d ' ')${CClear} configured" 68 "$crondiffon"
    menurow "(14)" "Always-alert watch over critical /etc files" "$(booleantoyesno "$enableetccritical")" 68 "$enablefsintegrity"
    menurow "(15)" "  Critical /etc files/folders to watch" "${CGreen}$(echo "$etccriticalpaths" | wc -w | tr -d ' ')${CClear} configured" 68 "$etccriticalon"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}  | ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( e)${CClear} : Return to Advanced Settings${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (1-15, e=Exit): " sel
    case "$sel" in
      1) [ "$enablefsintegrity" -eq 1 ] && { echo -e "Current: ${CGreen}${fsintegrityhrs}${CClear}"
         read -p "New filesystem-integrity scan interval in hours (>=1, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 1 && fsintegrityhrs="$val" && saveconfig; }; } ;;
      2) togglesetting enablefsintegrity ;;
      3) [ "$enablefsintegrity" -eq 1 ] && { if [ "$fsmodalertmode" = "hash" ]; then fsmodalertmode="mod"; else fsmodalertmode="hash"; fi; saveconfig; } ;;
      4) [ "$enablefsintegrity" -eq 1 ] && veditlist fswatchdirs "${advsettingsmenunum}.4.4 Watched Folders" "absolute path, e.g. /jffs/scripts" ;;
      5) [ "$enablefsintegrity" -eq 1 ] && veditlist fswatchexclude "${advsettingsmenunum}.4.5 Excluded Folder Names" "a folder NAME, not a path - matches this name anywhere under a watched folder, e.g. Backups" ;;
      6) [ "$enablefsintegrity" -eq 1 ] && veditlist fsexcludeext "${advsettingsmenunum}.4.6 Excluded File Extensions" "a file extension, e.g. .log (leading dot optional)" ;;
      7) [ "$enablefsintegrity" -eq 1 ] && veditlist fsexcludefiles "${advsettingsmenunum}.4.7 Excluded Individual Files" "a complete absolute file path, e.g. /jffs/scripts/sample.sh" ;;
      8) [ "$enablefsintegrity" -eq 1 ] && { echo -e "Current: ${CGreen}${fsmaxhashsize}${CClear}"
         read -p "New max hash size in bytes (>=1, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 1 && fsmaxhashsize="$val" && saveconfig; }; } ;;
      9) [ "$enablefsintegrity" -eq 1 ] && togglesetting enablequarantine ;;
      10) [ "$enablefsintegrity" -eq 1 ] && togglesetting enablefsdeletionwatch ;;
      11) [ "$enablefsintegrity" -eq 1 ] && togglesetting enablepermwatch ;;
      12) [ "$enablefsintegrity" -eq 1 ] && togglesetting enablecrondiff ;;
      13) [ "$crondiffon" -eq 1 ] && vcronexceptions ;;
      14) [ "$enablefsintegrity" -eq 1 ] && togglesetting enableetccritical ;;
      15) [ "$etccriticalon" -eq 1 ] && veditlist etccriticalpaths "${advsettingsmenunum}.4.15 Critical /etc Files/Folders" "an absolute /etc file or directory, e.g. /etc/shadow or /etc/pam.d" "A missing entry (e.g. an unused VPN subsystem) is silently skipped - no error, no alert." ;;
      [Ee]) break ;;
      [Ee]!) exitallmenus=1; break ;;
      *) ;;
    esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# vadvancednetwork: the router/network-level watches - conntrack (live traffic) and NVRAM (SSH/Telnet exposure, WAN DNS).

vadvancednetwork()
{
  while true; do
    [ "$exitallmenus" -eq 1 ] && break
    clear
    echo -en "${InvGreen} ${InvDkGray}${CWhite} "; padright "${advsettingsmenunum}.5 Advanced Settings - Network & System Watches" 136; echo -e "${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Controls watching active connections against known-malicious IPs, watching a short list of security-relevant router config state, and${CClear}"
    echo -e "${InvGreen} ${CClear} unexpected new WAN-exposure rules.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(1)${CClear} : "; padright "Watch active connections for traffic to known-malicious IPs" 68; echo -e ": $(booleantoyesno "$enableconntrackwatch")"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(2)${CClear} : "; padright "Watch security-relevant NVRAM vars (SSH/Telnet, WAN DNS, JFFS)" 68; echo -e ": $(booleantoyesno "$enablenvramwatch")"
    menurow "(3)" "Alert on new port-forward/DMZ/UPnP rules exposing LAN to WAN" "$(booleantoyesno "$enablefwrulediff")" 68 "$enablefsintegrity"
    menurow "(4)" "IP/CIDR Exceptions (excluded from conntrack feed matching)" "${CGreen}$(echo "$ipexceptions" | wc -w | tr -d ' ')${CClear} entries" 68 "$enableconntrackwatch"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(5)${CClear} : "; padright "Skynet Firewall Import Integration" 68; echo -e ": $(booleantoyesno "$enableskynetimport")"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite} | ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(e)${CClear} : Return to Advanced Settings${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (1-5, e=Exit): " sel
    case "$sel" in
      1) togglesetting enableconntrackwatch ;;
      2) togglesetting enablenvramwatch ;;
      3) [ "$enablefsintegrity" -eq 1 ] && togglesetting enablefwrulediff ;;
      4) [ "$enableconntrackwatch" -eq 1 ] && veditlist ipexceptions "${advsettingsmenunum}.5.4 IP/CIDR Exceptions" "a single IP, e.g. 204.44.63.22, or a CIDR range, e.g. 204.44.0.0/16" \
           "A single IP (204.44.63.22) or a CIDR range (204.44.0.0/16) that conntrack should never compare" \
           "against a feed - checked and excluded first, before any feed indicator is ever considered." ;;
      5) vskynetintegration ;;
      [Ee]) break ;;
      [Ee]!) exitallmenus=1; break ;;
      *) ;;
    esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# vskynetintegration is the pop-out explanation/confirmation screen for enabling or disabling the Skynet import

vskynetintegration()
{
  local sel detecteddisp skrc beforecount

  while true; do
    [ "$exitallmenus" -eq 1 ] && break
    clear
    echo -en "${InvGreen} ${InvDkGray}${CWhite} "; padright "${advsettingsmenunum}.5.5 Skynet Firewall Import Integration" 136; echo -e "${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} If Skynet Firewall is installed, IOCMON can push its own current IPv4 threat-feed indicators directly into Skynet's ban list, tagged${CClear}"
    echo -e "${InvGreen} ${CClear} \"IOCMON\" so they are always identifiable and can be found or removed independently of Skynet's own manual and automatic bans.${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} This goes beyond Skynet's own Custom Filter URL feature: that only ever pulls one static, user-chosen list on Skynet's own schedule,${CClear}"
    echo -e "${InvGreen} ${CClear} while this keeps IOCMON's own multi-source feed set (Feodo, Spamhaus, NetAPI, URLhaus, ThreatFox, and optionally Q-Feeds) continuously${CClear}"
    echo -e "${InvGreen} ${CClear} in sync with Skynet's live ban list. The import runs automatically every time IOCMON refreshes its threat feeds (see General Settings${CClear}"
    echo -e "${InvGreen} ${CClear} for that interval), not just once at setup.${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} These are fresh, continuously-updated security indicators, not a hand-curated list, so false positives are possible. Once imported, and${CClear}"
    echo -e "${InvGreen} ${CClear} if Skynet is itself configured to block both directions, every one of these IPs will have its inbound AND outbound traffic denied,${CClear}"
    echo -e "${InvGreen} ${CClear} which gives IOCMON better blocking (IDS/IPS) capabilities, not just read-only alerting.${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} NOTE: Q-Feeds adds 200,000+ lower-confidence OSINT entries on top of the much smaller, higher-confidence core feeds. Item (2) below${CClear}"
    echo -e "${InvGreen} ${CClear} controls whether those are optionally included in this import too.${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Disabling this feature removes every IOCMON-tagged entry from Skynet first, before the setting is saved. Items (3) and (4) below${CClear}"
    echo -e "${InvGreen} ${CClear} let you force a fresh import or a full removal on demand, without waiting for the next scheduled feed refresh.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"

    if skynetinstalled; then detecteddisp="${CGreen}Yes${CClear} (${skynetstoragepath})"; else detecteddisp="${CYellow}Not detected${CClear}"; fi
    echo -e "${InvGreen} ${CClear} Skynet detected: ${detecteddisp}${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(1)${CClear} : "; padright "Enable/Disable Skynet Firewall Import Integration" 78; echo -e ": $(booleantoyesno "$enableskynetimport")"
    menurow "(2)" "Also include Q-Feeds' larger, lower-confidence IP list in that import" "$(booleantoyesno "$skynetimportqfeeds")" 78 "$enableskynetimport"
    menurow "(3)" "Force a Skynet import now, from currently downloaded feeds (no new download)" "${CGreen}Run Now${CClear}" 78 "$enableskynetimport"
    menurow "(4)" "Remove all IOCMON-tagged entries from Skynet's ban list right now" "${CGreen}Run Now${CClear}" 78 "$enableskynetimport"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite} | ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(e)${CClear} : Return to Network & System Watches${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (1-4, e=Exit): " sel
    case "$sel" in
      1)
        if [ "$enableskynetimport" -eq 1 ]; then
          echo ""
          echo -e "Disable Skynet Firewall Import Integration?"
          if promptyn "[y/n]: "; then
            echo ""
            inlinestatus "Removing IOCMON-tagged entries from Skynet"
            removeskynetimports
            enableskynetimport=0
            resolvefeedsroot
            [ -n "$feedsroot" ] && rm -f "$feedsroot/meta/skynet_import.hash"
            saveconfig
            echo -e "\33[2K\r${CGreen}Skynet integration disabled - removed ${skynetremovedcount:-0} IOCMON-tagged entry/entries from Skynet's ban list.${CClear}"
            echo ""
            read -rsp $'Press any key to continue...\n' -n1 key
          fi
        else
          echo ""
          echo -e "Enable Skynet Firewall Import Integration?"
          if promptyn "[y/n]: "; then
            echo ""
            if ! skynetinstalled; then
              echo -e "${CRed}Skynet was not detected at /jffs/scripts/firewall - install it first, then come back here.${CClear}"
            else
              enableskynetimport=1
              saveconfig
              resolvefeedsroot
              if [ -n "$feedsroot" ]; then
              	echo ""
                echo -e "Importing current feed indicators into Skynet now..."
                echo ""
                syncskynetimport; skrc=$?
                case "$skrc" in
                  0) echo -e "\33[2K\r${CGreen}Imported ${skynetimportcount:-0} IPv4 indicator(s) into Skynet's ban list, tagged IOCMON.${CClear}" ;;
                  1) echo -e "\33[2K\r${CGreen}Enabled - nothing to import yet (no feed indicators, or none past your IP/CIDR Exceptions).${CClear}" ;;
                  *) echo -e "\33[2K\r${CRed}Enabled, but the first import failed - check ${logfile} for details. IOCMON will retry on the next feed refresh.${CClear}" ;;
                esac
              else
                echo -e "${CYellow}Enabled - no feed-storage location is resolved yet, so the first import will happen once one is.${CClear}"
              fi
            fi
            echo ""
            read -rsp $'Press any key to continue...\n' -n1 key
          fi
        fi
      ;;
      2) [ "$enableskynetimport" -eq 1 ] && togglesetting skynetimportqfeeds ;;
      3)
        if [ "$enableskynetimport" -eq 1 ]; then
          echo ""
          if ! skynetinstalled; then
            echo -e "${CRed}Skynet was not detected at /jffs/scripts/firewall - nothing to import into.${CClear}"
          else
            resolvefeedsroot
            if [ -z "$feedsroot" ]; then
              echo -e "${CYellow}No feed-storage location is resolved yet - nothing to import from.${CClear}"
            else
              echo -e "Recompiling the Skynet import file from currently downloaded feeds and importing now..."
              echo ""
              syncskynetimport force; skrc=$?
              case "$skrc" in
                0) echo -e "\33[2K\r${CGreen}Imported ${skynetimportcount:-0} IPv4 indicator(s) into Skynet's ban list, tagged IOCMON.${CClear}" ;;
                1) echo -e "\33[2K\r${CGreen}Nothing to import - no feed indicators are currently downloaded, or none past your IP/CIDR Exceptions.${CClear}" ;;
                *) echo -e "\33[2K\r${CRed}Import failed - check ${logfile} for details.${CClear}" ;;
              esac
            fi
          fi
          echo ""
          read -rsp $'Press any key to continue...\n' -n1 key
        fi
      ;;
      4)
        if [ "$enableskynetimport" -eq 1 ]; then
          echo ""
          if ! skynetinstalled; then
            echo -e "${CRed}Skynet was not detected at /jffs/scripts/firewall - nothing to remove.${CClear}"
          else
            beforecount="$(skynetimportids | wc -l | tr -d ' ')"
            if [ "$beforecount" -eq 0 ]; then
              echo -e "${CGreen}No IOCMON-tagged entries are currently present in Skynet's ban list.${CClear}"
            else
              inlinestatus "Removing IOCMON-tagged entries from Skynet"
              removeskynetimports
              resolvefeedsroot
              [ -n "$feedsroot" ] && rm -f "$feedsroot/meta/skynet_import.hash"
              echo -e "\33[2K\r${CGreen}Removed ${skynetremovedcount:-0} of ${beforecount} IOCMON-tagged entry/entries from Skynet's ban list.${CClear}"
              echo -e "${CDkGray}The next feed refresh (or item (3) above) will re-import a fresh list, since integration is still enabled.${CClear}"
            fi
          fi
          echo ""
          read -rsp $'Press any key to continue...\n' -n1 key
        fi
      ;;
      [Ee]) break ;;
      [Ee]!) exitallmenus=1; break ;;
      *) ;;
    esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# vadvancedgeneral: everything about how the script itself runs/schedules/updates

vadvancedgeneral()
{
  while true; do
    [ "$exitallmenus" -eq 1 ] && break
    clear
    echo -en "${InvGreen} ${InvDkGray}${CWhite} "; padright "${advsettingsmenunum}.6 Advanced Settings - General / Script Behavior" 136; echo -e "${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Controls the main loop's own cadence, log size and location, autostart, IOCMON's self-update schedule/track and the optional router${CClear}"
    echo -e "${InvGreen} ${CClear} web interface tab - not specific to any one detection watch.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(1)${CClear} : "; padright "Main loop / detection refresh interval, in seconds" 68; echo -e ": ${CGreen}$timerloop${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(2)${CClear} : "; padright "Rows before each log is rotated to .1 and .2 (0 = never)" 68; echo -e ": ${CGreen}$logsize${CClear}"
    logloconly=0; [ -n "$extdrivelabel" ] && logloconly=1
    menurow "(3)" "IOCMON Activity Log folder location" "${CGreen}${logfilepath:-$jffslogfile}${CClear}" 68 "$logloconly"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(4)${CClear} : "; padright "Launch IOCMON automatically in the background after a reboot" 68; echo -e ": $(booleantoyesno "$autostart")"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(5)${CClear} : "; padright "Check for IOCMON script updates on a daily schedule" 68; echo -e ": $(booleantoyesno "$schedule")"
    menurow "(6)" "  Time of day for that update check (24-hour clock)" "${CGreen}$(printf '%02d' "$schedulehrs"):$(printf '%02d' "$schedulemin")${CClear}" 68 "$schedule"
    menurow "(7)" "Automatically install IOCMON script updates when found" "$(booleantoyesno "$updateiocm")" 68 "$schedule"
    if [ "$track" = "0" ]; then trackdisp="Stable"; tracklabel="STABLE"; else trackdisp="Beta"; tracklabel="BETA"; fi
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(8)${CClear} : "; padright "Update track" 68; echo -e ": ${CGreen}${trackdisp}${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(9)${CClear} : "; padright "Router web interface tab (Addons > IOCMON)" 68; echo -e ": $(booleantoyesno "$enablewebui")"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite} | ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(e)${CClear} : Return to Advanced Settings${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (1-9, e=Exit): " sel
    case "$sel" in
      1) echo -e "Current: ${CGreen}${timerloop}${CClear}"
         read -p "New main loop interval in seconds (>=5, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 5 && timerloop="$val" && saveconfig; } ;;
      2) echo -e "Current: ${CGreen}${logsize}${CClear}"
         read -p "Rows before each log is rotated (0=never, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 0 && logsize="$val" && saveconfig; } ;;
      3) [ "$logloconly" -eq 1 ] && vlogfilelocation ;;
      4) togglesetting autostart ;;
      5) togglesetting schedule ;;
      6) [ "$schedule" -eq 1 ] && { echo -e "Current: ${CGreen}$(printf '%02d' "$schedulehrs"):$(printf '%02d' "$schedulemin")${CClear}"
         read -p "New self-update hour (0-23, blank to keep current): " newhr
         read -p "New self-update minute (0-59, blank to keep current): " newmin
         [ -z "$newhr" ] && newhr="$schedulehrs"
         [ -z "$newmin" ] && newmin="$schedulemin"
         if validateint "$newhr" 0 && [ "$newhr" -le 23 ] && validateint "$newmin" 0 && [ "$newmin" -le 59 ]; then
           schedulehrs="$newhr"; schedulemin="$newmin"; saveconfig
         fi; } ;;
      7) [ "$schedule" -eq 1 ] && togglesetting updateiocm ;;
      8) togglesetting track ;;
      9) vwebuitoggle ;;
      [Ee]) break ;;
      [Ee]!) exitallmenus=1; break ;;
      *) ;;
    esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# vlogfilelocation swaps the activity log between JFFS and the external drive's state folder, after a y/n confirmation

vlogfilelocation()
{
  local target

  resolveiocmonroot
  if [ -z "$logfilepath" ] || [ "$logfilepath" = "$jffslogfile" ]; then
    target="$iocmonroot/state/iocmon.log"
  else
    target="$jffslogfile"
  fi

  echo ""
  if [ "$target" != "$jffslogfile" ] && [ ! -d "$iocmonroot" ]; then
    echo -e "${CRed}The external drive (label=$extdrivelabel) is not currently mounted - the log can't be moved there right now.${CClear}"
    echo ""
    read -rsp $'Press any key to continue...\n' -n1 key
    return
  fi

  echo -e "Current location: ${CGreen}${logfilepath:-$jffslogfile}${CClear}"
  echo -e "New location    : ${CGreen}${target}${CClear}"
  echo ""
  echo -e "Are you sure you want to move the IOCMON activity log to this new location?"
  if promptyn "[y/n]: "; then
    echo ""
    echo ""
    if relocatelogfile "$target"; then
      saveconfig
      echo -e "${CGreen}The activity log now lives at $target.${CClear}"
    else
      resolvelogfile
      echo -e "${CRed}The activity log could not be moved to $target - its location was left unchanged.${CClear}"
    fi
    echo ""
    read -rsp $'Press any key to continue...\n' -n1 key
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# feedkeycell prints the right-hand API-key cell of a menu 2 toggle row, dimmed when $4 is 0

feedkeycell()
{
  if [ "$4" -eq 1 ]; then
    printf '%s' "   |  ${InvDkGray}${CWhite}$1${CClear} : $(padright "$2" 19): ${CGreen}$3${CClear}"
  else
    printf '%s' "   |  ${CDkGray}$1${CClear} : $(padright "${CDkGray}$2${CClear}" 19): ${CDkGray}$3${CClear}"
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# feedsaveconfig saves menu 2, writing any key-dependent feed as off on disk while it is switched on without a key

feedsaveconfig()
{
  local pendqf="$enableqfeeds" pendaipdb="$enableabuseipdb" penduh="$enableurlhaus" pendtf="$enablethreatfox"
  [ -z "$qfeedsapikey" ] && enableqfeeds=0
  [ -z "$abuseipdbapikey" ] && enableabuseipdb=0
  [ -z "$urlhausapikey" ] && enableurlhaus=0
  [ -z "$threatfoxapikey" ] && enablethreatfox=0
  saveconfig
  enableqfeeds="$pendqf"; enableabuseipdb="$pendaipdb"; enableurlhaus="$penduh"; enablethreatfox="$pendtf"
}

# -------------------------------------------------------------------------------------------------------------------------
# feedkeylessrevert switches Q-Feeds/AbuseIPDB back off on leaving menu 2 if either was switched on but no key was entered

feedkeylessrevert()
{
  local reverted
  reverted="$(keylessfeeds)"
  [ -n "$reverted" ] || return
  [ -z "$urlhausapikey" ] && enableurlhaus=0
  [ -z "$threatfoxapikey" ] && enablethreatfox=0
  [ -z "$qfeedsapikey" ] && enableqfeeds=0
  [ -z "$abuseipdbapikey" ] && enableabuseipdb=0
  saveconfig
  echo ""
  echo -e "${CYellow}$reverted left switched off - no API key was entered.${CClear}"; sleep 3
}

# -------------------------------------------------------------------------------------------------------------------------
# keylessfeeds echoes a comma-separated list of the key-dependent feeds currently switched on without a key

keylessfeeds()
{
  local list=""
  [ "$enableurlhaus" -eq 1 ] && [ -z "$urlhausapikey" ] && list="URLhaus"
  [ "$enablethreatfox" -eq 1 ] && [ -z "$threatfoxapikey" ] && list="${list:+$list, }ThreatFox"
  [ "$enableqfeeds" -eq 1 ] && [ -z "$qfeedsapikey" ] && list="${list:+$list, }Q-Feeds"
  [ "$enableabuseipdb" -eq 1 ] && [ -z "$abuseipdbapikey" ] && list="${list:+$list, }AbuseIPDB"
  echo "$list"
}

# -------------------------------------------------------------------------------------------------------------------------
# abusechkeyoffer offers to reuse the other abuse.ch feed's Auth-Key when URLhaus/ThreatFox ($1) is switched on without one

abusechkeyoffer()
{
  local other otherkey
  if [ "$1" = "urlhaus" ]; then
    [ -n "$urlhausapikey" ] && return
    other="ThreatFox"; otherkey="$threatfoxapikey"
  else
    [ -n "$threatfoxapikey" ] && return
    other="URLhaus"; otherkey="$urlhausapikey"
  fi
  [ -n "$otherkey" ] || return
  echo ""
  echo -e "Your $other Auth-Key is an abuse.ch key, and one abuse.ch key works for both URLhaus and ThreatFox."
  echo ""
  if promptyn "Use the same key here? [y/n]: "; then
    echo ""
    if [ "$1" = "urlhaus" ]; then urlhausapikey="$otherkey"; else threatfoxapikey="$otherkey"; fi
  else
    echo ""
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# migratefeedkeys switches off, once at startup, any key-dependent feed left on without a key (e.g. URLhaus/ThreatFox from before keys were required)

migratefeedkeys()
{
  local reverted
  reverted="$(keylessfeeds)"
  [ -n "$reverted" ] || return
  [ -z "$urlhausapikey" ] && enableurlhaus=0
  [ -z "$threatfoxapikey" ] && enablethreatfox=0
  [ -z "$qfeedsapikey" ] && enableqfeeds=0
  [ -z "$abuseipdbapikey" ] && enableabuseipdb=0
  saveconfig
  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: $reverted switched off - an API key is now required (abuse.ch no longer offers keyless URLhaus/ThreatFox downloads). Set it under Configuration Menu 2." >> "$logfile"
}

# -------------------------------------------------------------------------------------------------------------------------
# abusechemaillinks prints abuse.ch lookup links (email HTML) for an alert whose source ($3) includes urlhaus/threatfox

abusechemaillinks()
{
  local kind="$1" indicator="$2" source="$3" detail="$4" value=""
  case "$source" in *urlhaus*|*threatfox*) ;; *) return ;; esac
  case "$kind" in
    conntrack|dns) value="${indicator#*->}" ;;
    fsintegrity) value="$(echo "$detail" | sed -n 's/^hash match \([0-9a-fA-F]*\).*/\1/p')" ;;
  esac
  [ -n "$value" ] || return
  case "$source" in *urlhaus*)
    if [ "$kind" = "fsintegrity" ]; then emaillinkrow "URLhaus" "https://urlhaus.abuse.ch/browse.php?search=$value"
    else emaillinkrow "URLhaus" "https://urlhaus.abuse.ch/host/$value/"; fi ;;
  esac
  case "$source" in *threatfox*)
    emaillinkrow "ThreatFox" "https://threatfox.abuse.ch/browse.php?search=ioc%3A$value" ;;
  esac
}

# -------------------------------------------------------------------------------------------------------------------------
# lookuprow prints one "label : value" row of the lookup screen in colour $3, word-wrapped to the screen width

lookuprow()
{
  local label="$1" color="${3:-$CClear}" first=1 ln
  printf '%s\n' "$2" | awk -v w=110 '
    { gsub(/[[:cntrl:]]/, ""); v = (NR == 1 ? $0 : v " " $0) }
    END {
      n = split(v, wd, " "); line = ""
      for (i = 1; i <= n; i++) {
        while (length(wd[i]) > w) { r = (line == "" ? w : w - length(line) - 1); if (r < 10) { print line; line = ""; r = w } line = (line == "" ? "" : line " ") substr(wd[i], 1, r); print line; line = ""; wd[i] = substr(wd[i], r + 1) }
        if (line == "") line = wd[i]
        else if (length(line) + 1 + length(wd[i]) <= w) line = line " " wd[i]
        else { print line; line = wd[i] }
      }
      print line
    }' | while IFS= read -r ln; do
    printf '%b   ' "${InvGreen} ${CClear}"
    if [ "$first" -eq 1 ] && [ -n "$label" ]; then padexact "$label" 22; printf ': '; else printf '%24s' ""; fi
    first=0
    printf '%b%s%b\n' "$color" "$ln" "$CClear"
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# lookupsection prints a white section heading with a blank sidebar line above it

lookupsection()
{
  echo -e "${InvGreen} ${CClear}"
  echo -e "${InvGreen} ${CClear} ${CWhite}$1${CClear}"
}

# -------------------------------------------------------------------------------------------------------------------------
# lookupnormalize cleans a typed indicator (case, scheme, path, port, defanged dots) and echoes ip|<v>, domain|<v>, ipv6|<v> or nothing

lookupnormalize()
{
  local v
  v="$(printf '%s' "$1" | tr 'A-Z' 'a-z' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//; s/\[\.\]/./g; s/(\.)/./g; s/^hxxp/http/; s|^[a-z][a-z0-9+.-]*://||; s|[/?#].*$||; s/^.*@//')"
  case "$v" in
    *:*:*|\[*) echo "ipv6|$v"; return ;;
  esac
  v="$(printf '%s' "$v" | sed 's/:[0-9]*$//; s/\.$//')"
  if echo "$v" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
    echo "$v" | awk -F. '{ for (i = 1; i <= 4; i++) if ($i + 0 > 255) exit 1 }' && echo "ip|$v"
  elif echo "$v" | grep -qE '^[a-z0-9_-]+(\.[a-z0-9_-]+)+$' && echo "$v" | grep -q '[a-z]'; then
    echo "domain|$v"
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# lookupipfeeds prints entry|sources|families for every loaded feed entry equal to IP $1 or a netblock containing it

lookupipfeeds()
{
  local ip="$1" qf="$feedsroot/qfeeds_ips.txt"
  set --
  [ -s "$feedsroot/ips.txt" ] && set -- "$@" "$feedsroot/ips.txt"
  [ -s "$qf" ] && set -- "$@" "$qf"
  [ "$#" -gt 0 ] || return 0
  awk -F'|' -v ip="$ip" -v qf="$qf" '
    function toint(s,  a) { split(s, a, "."); return a[1] * 16777216 + a[2] * 65536 + a[3] * 256 + a[4] }
    BEGIN { t = toint(ip) }
    {
      e = $1; sub(/\r$/, "", e)
      if (FILENAME == qf) { s = "qfeeds"; f = "osint-ip" } else { s = $2; f = $3 }
      hit = (e == ip)
      if (!hit && index(e, "/")) { split(e, p, "/"); m = p[2] + 0; if (m >= 0 && m <= 32) { d = 2 ^ (32 - m); hit = (int(t / d) == int(toint(p[1]) / d)) } }
      if (hit) print e "|" s "|" f
    }' "$@"
}

# -------------------------------------------------------------------------------------------------------------------------
# lookupdomainfeeds prints E|, P| (listed parent) or S| (listed subdomain) entry|sources|families for domain $1 in the loaded feeds

lookupdomainfeeds()
{
  local d="$1" qf="$feedsroot/qfeeds_domains.txt"
  set --
  [ -s "$feedsroot/domains.txt" ] && set -- "$@" "$feedsroot/domains.txt"
  [ -s "$qf" ] && set -- "$@" "$qf"
  [ "$#" -gt 0 ] || return 0
  awk -F'|' -v d="$d" -v qf="$qf" '
    BEGIN { n = split(d, l, "."); for (i = 2; i < n; i++) { p = l[i]; for (j = i + 1; j <= n; j++) p = p "." l[j]; par[p] = 1 }; dl = length(d) }
    {
      e = $1; sub(/\r$/, "", e)
      if (FILENAME == qf) { s = "qfeeds"; f = "osint-domain" } else { s = $2; f = $3 }
      if (e == d) print "E|" e "|" s "|" f
      else if (e in par) print "P|" e "|" s "|" f
      else if (length(e) > dl && substr(e, length(e) - dl) == "." d) print "S|" e "|" s "|" f
    }' "$@"
}

# -------------------------------------------------------------------------------------------------------------------------
# lookupfeedmatch prints one feed-match block (entry, feeds, each family piece, Spamhaus SBL reference) for entry|sources|families $1

lookupfeedmatch()
{
  local entry srcs fams note="$2" sbl fam first=1
  IFS='|' read -r entry srcs fams <<EOF
$1
EOF
  echo -e "${InvGreen} ${CClear}"
  lookuprow "Listed entry" "$entry${note:+ ($note)}" "$CRed"
  lookuprow "Feed(s)" "$(emailfeedname "$srcs")"
  echo "$fams" | tr ',' '\n' | sed 's/^ *//; s/ *$//' | grep . | while IFS= read -r fam; do
    if [ "$first" -eq 1 ]; then lookuprow "Details" "$fam"; first=0; else lookuprow "" "$fam"; fi
  done
  case "$srcs" in *spamhaus*)
    sbl="$(cat "$feedsroot/spamhaus_drop.raw" "$feedsroot/spamhaus_edrop.raw" 2>/dev/null | awk -v e="$entry" '$1 == e { for (i = 2; i <= NF; i++) if ($i ~ /^SBL[0-9]+$/) { print $i; exit } }')"
    [ -n "$sbl" ] && lookuprow "Spamhaus reference" "$sbl"
  esac
}

# -------------------------------------------------------------------------------------------------------------------------
# lookupurlhausraw prints a summary and the newest 5 records of host $1 from the full URLhaus download (online and offline)

lookupurlhausraw()
{
  local out total online first last threats tags rest ln
  [ "$enableurlhaus" = "1" ] && grep -q '^"[0-9]' "$feedsroot/urlhaus.raw" 2>/dev/null || return 0
  grep -qF "$1" "$feedsroot/urlhaus.raw" || return 0
  out="$(awk -v h="$1" '
    /^"[0-9]/ {
      line = $0; sub(/\r$/, "", line); sub(/^"/, "", line); sub(/"$/, "", line)
      if (split(line, f, /","/) < 7) next
      host = f[3]; sub(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, "", host); sub(/[\/?#].*$/, "", host); sub(/^.*@/, "", host); sub(/:[0-9]+$/, "", host)
      if (tolower(host) != h) next
      n++; if (f[4] == "online") on++
      if (first == "" || f[2] < first) first = f[2]
      if (f[2] > last) last = f[2]
      if (f[6] != "" && index(" " thr " ", " " f[6] " ") == 0) thr = (thr == "" ? f[6] : thr " " f[6])
      nt = split(f[7], tg, ",")
      for (i = 1; i <= nt; i++) { g = tg[i]; gsub(/^ +| +$/, "", g); if (g != "" && g != "None" && index(" " tags " ", " " g " ") == 0) tags = (tags == "" ? g : tags " " g) }
      if (n <= 5) rec[n] = f[2] "\037" f[4] "\037" f[3]
    }
    END {
      if (n == 0) exit
      print n "\037" on + 0 "\037" first "\037" last "\037" thr "\037" tags
      for (i = 1; i <= n && i <= 5; i++) print rec[i]
    }' "$feedsroot/urlhaus.raw")"
  [ -n "$out" ] || return 0
  IFS="$(printf '\037')" read -r total online first last threats tags <<EOF
$(echo "$out" | head -n 1)
EOF
  lookupsection "URLhaus Records (the full download, online and offline - DNS watch only uses online or recent ones)"
  lookuprow "URLs listed" "$total ($online online)"
  lookuprow "First / last added" "$first / $last UTC"
  lookuprow "Threat" "${threats:-n/a}"
  lookuprow "Tags" "${tags:-none}"
  echo "$out" | sed 1d | while IFS="$(printf '\037')" read -r first online rest; do
    lookuprow " $first" "[$online] $rest" "$CDkGray"
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# lookupthreatfoxraw prints every ThreatFox record (up to 5) whose IOC, ip:port or URL host is $1, from the API download

lookupthreatfoxraw()
{
  local out id ioc typ tt mal alias conf fs ls rep ref tags n=0
  [ "$enablethreatfox" = "1" ] && [ -s "$feedsroot/threatfox.raw" ] && [ "$(cat "$feedsroot/meta/threatfox.mode" 2>/dev/null)" = "api" ] || return 0
  grep -qF "$1" "$feedsroot/threatfox.raw" || return 0
  out="$(awk -v RS='}' -v t="$1" '
    function jv(k,  r) {
      if (match($0, "\"" k "\"[[:space:]]*:[[:space:]]*\"[^\"]*\"")) { r = substr($0, RSTART, RLENGTH); sub(/^[^:]*:[[:space:]]*"/, "", r); sub(/"$/, "", r); gsub("\\\\/", "/", r); gsub(/[[:cntrl:]]/, " ", r); return r }
      if (match($0, "\"" k "\"[[:space:]]*:[[:space:]]*[0-9]+")) { r = substr($0, RSTART, RLENGTH); sub(/^[^:]*:[[:space:]]*/, "", r); return r }
      return ""
    }
    function jt(  r) { if (match($0, /"tags"[[:space:]]*:[[:space:]]*\[[^]]*\]/)) { r = substr($0, RSTART, RLENGTH); sub(/^[^[]*\[/, "", r); sub(/\]$/, "", r); gsub(/"/, "", r); gsub(/[[:space:]]*,[[:space:]]*/, " ", r); gsub(/^[[:space:]]+|[[:space:]]+$/, "", r); return r } return "" }
    {
      v = tolower(jv("ioc")); typ = jv("ioc_type"); if (v == "") next
      h = v
      if (typ == "ip:port") sub(/:[0-9]+$/, "", h)
      else if (typ == "url") { sub(/^[a-z]+:\/\//, "", h); sub(/[\/?#].*$/, "", h); sub(/^.*@/, "", h); sub(/:[0-9]+$/, "", h) }
      if (h != t) next
      n++
      if (n <= 5) printf "%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\n", jv("id"), jv("ioc"), typ, jv("threat_type"), jv("malware_printable"), jv("malware_alias"), jv("confidence_level"), jv("first_seen"), jv("last_seen"), jv("reporter"), jv("reference"), jt()
    }
    END { if (n > 5) print "MORE\037" n }' "$feedsroot/threatfox.raw")"
  [ -n "$out" ] || return 0
  lookupsection "ThreatFox Records (the API download)"
  echo "$out" | while IFS="$(printf '\037')" read -r id ioc typ tt mal alias conf fs ls rep ref tags; do
    if [ "$id" = "MORE" ]; then lookuprow "" "... $ioc records in all, the newest 5 are shown" "$CDkGray"; continue; fi
    echo -e "${InvGreen} ${CClear}"
    lookuprow "IOC" "$ioc ($typ)" "$CRed"
    lookuprow "Malware" "${mal:-n/a}${alias:+ (also known as $alias)}"
    lookuprow "Threat / confidence" "${tt:-n/a} / ${conf:-n/a}%"
    lookuprow "First / last seen" "${fs:-n/a} / ${ls:-n/a}"
    lookuprow "Reporter" "${rep:-n/a}"
    lookuprow "Tags" "${tags:-none}"
    [ -n "$ref" ] && lookuprow "Reference" "$ref"
    [ -n "$id" ] && lookuprow "ThreatFox entry" "https://threatfox.abuse.ch/ioc/$id/"
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# lookuphistory prints how often IOCMON itself alerted on $1 ($2=domain also counts subdomains), with the newest 5 entries

lookuphistory()
{
  local out total d k ind sev
  resolvestateroot
  lookupsection "Local Alert History (IOCMON's own IoC detections log)"
  if [ -z "$stateroot" ]; then lookuprow "History" "not available without the external drive" "$CDkGray"; return; fi
  out="$(logall "$stateroot/ioc_alerts.log" | grep -F "$1" | awk -F'|' -v t="$1" -v dom="$2" '
    function trim(s) { sub(/^ +/, "", s); sub(/ +$/, "", s); return s }
    {
      ind = trim($3); h = ind; sub(/^.*->/, "", h); h = tolower(h)
      if (!(h == t || (dom == "domain" && length(h) > length(t) && substr(h, length(h) - length(t)) == "." t))) next
      sev = trim($NF); if (sev ~ /^sev:/) sev = substr(sev, 5); else sev = ""
      n++; line[n] = trim($1) "\037" trim($2) "\037" ind "\037" sev
    }
    END { if (n == 0) exit; print n; for (i = n; i > 0 && i > n - 5; i--) print line[i] }')"
  if [ -z "$out" ]; then lookuprow "Alerts" "none - IOCMON has not alerted on this indicator" "$CGreen"; return; fi
  total="$(echo "$out" | head -n 1)"
  lookuprow "Alerts" "$total (newest first, up to 5 shown)" "$CYellow"
  echo "$out" | sed 1d | while IFS="$(printf '\037')" read -r d k ind sev; do
    lookuprow " $d" "$k  $ind${sev:+  [$sev]}"
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# lookupexceptions prints whether IP or domain $2 ($1=ip|domain) sits on an exception or shared-hosting list

lookupexceptions()
{
  local hit=""
  lookupsection "Exception Lists"
  if [ "$1" = "ip" ]; then
    ispublicip "$2" || lookuprow "Address" "private or reserved - conntrack only matches public destinations" "$CYellow"
    hit="$(awk -v ip="$2" -v exc="$ipexceptions" '
      function toint(s,  a) { split(s, a, "."); return a[1] * 16777216 + a[2] * 65536 + a[3] * 256 + a[4] }
      BEGIN {
        n = split(exc, e, " "); t = toint(ip)
        for (i = 1; i <= n; i++) {
          if (e[i] == ip) { print e[i]; exit }
          if (split(e[i], p, "/") == 2 && p[2] + 0 >= 0 && p[2] + 0 <= 32) { d = 2 ^ (32 - p[2]); if (int(t / d) == int(toint(p[1]) / d)) { print e[i]; exit } }
        }
      }')"
    if [ -n "$hit" ]; then lookuprow "IP/CIDR exceptions" "yes, covered by $hit - conntrack never alerts on it" "$CYellow"
    else lookuprow "IP/CIDR exceptions" "no"; fi
  else
    for hit in $dnsexceptions; do case "$2" in "$hit"|*".$hit") break ;; esac; hit=""; done
    if [ -n "$hit" ]; then lookuprow "DNS exceptions" "yes, covered by $hit - DNS watch never alerts on it" "$CYellow"
    else lookuprow "DNS exceptions" "no"; fi
    hit=""
    for hit in $dnssharedhosts; do case "$2" in "$hit"|*".$hit") break ;; esac; hit=""; done
    if [ -n "$hit" ]; then lookuprow "Shared-hosting list" "yes, covered by $hit - a DNS feed match is logged as Info" "$CYellow"
    else lookuprow "Shared-hosting list" "no"; fi
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# lookupreputation offers a live AbuseIPDB check of IP $1 (or a domain's last DNS answer, $2=domain), showing a cached result without asking

lookupreputation()
{
  local ip="$1" what="$2" rec rip epoch score total users last cc cname usage isp domain tor wl hostnames cats color
  lookupsection "AbuseIPDB Reputation"
  if [ "$enableabuseipdb" != "1" ] || [ -z "$abuseipdbapikey" ]; then
    lookuprow "AbuseIPDB" "off - switch it on with item 12 and set its key with item 13" "$CDkGray"; return
  fi
  if [ "$what" = "domain" ]; then
    ip="$(dnsreplyip "$1")"
    if [ -z "$ip" ]; then lookuprow "AbuseIPDB" "not checked - no public IP for this domain in the DNS reply log (IOCMON never resolves it itself)" "$CDkGray"; return; fi
    lookuprow "Last DNS answer" "$ip"
  fi
  if ! ispublicip "$ip"; then lookuprow "AbuseIPDB" "not checked - $ip is not a public IP address" "$CDkGray"; return; fi
  resolvestateroot
  if [ -z "$(abuseipdbcached "$ip")" ]; then
    echo -e "${InvGreen} ${CClear}"
    echo ""
    if ! promptyn "Check $ip on AbuseIPDB now? It uses 1 of today's lookups ($(abuseipdbusedtoday) of $abuseipdbdailymax used) [y/n]: "; then
      echo ""; echo ""
      lookuprow "AbuseIPDB" "not checked" "$CDkGray"; return
    fi
    echo ""
  fi
  reputationlookup lookup "$ip" manual
  printf '\33[2K\r'
  rec=""
  [ -n "$repip" ] && rec="$(awk -F'|' -v ip="$repip" '$1 == ip' "$stateroot/abuseipdb_cache.db" 2>/dev/null | tail -n 1)"
  if [ -n "$rec" ]; then
    IFS='|' read -r rip epoch score total users last cc cname usage isp domain tor wl hostnames cats <<EOF
$rec
EOF
    color="$CGreen"; [ "$score" -ge 25 ] && color="$CYellow"; [ "$score" -ge 75 ] && color="$CRed"
    echo ""
    lookuprow "Score" "${score}% abuse confidence" "$color"
    lookuprow "Reports" "$total from $users distinct user(s) in the last $abuseipdbmaxage days"
    lookuprow "Last report" "${last:-never}"
    lookuprow "Categories" "${cats:-none}"
    lookuprow "Country" "${cname:-${cc:-unknown}}${cname:+ (${cc})}"
    lookuprow "Usage type / ISP" "${usage:-n/a} / ${isp:-n/a}"
    lookuprow "Domain / hostnames" "${domain:-n/a} / ${hostnames:-none}"
    lookuprow "Tor / whitelisted" "${tor:-n/a} / ${wl:-n/a}"
  else
    lookuprow "AbuseIPDB" "not checked - ${repreason:-no lookup was made}" "$CDkGray"
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# lookupresults searches every loaded feed for IP or domain $2 ($1=ip|domain) and prints all findings

lookupresults()
{
  local kind="$1" v="$2" matches exact parents subs nsubs feedcount=0 enc="$2"
  inlinestatus "Searching the feeds for $v"
  if [ "$kind" = "ip" ]; then
    exact="$(lookupipfeeds "$v")"
  else
    matches="$(lookupdomainfeeds "$v")"
    exact="$(echo "$matches" | sed -n 's/^E|//p')"
    parents="$(echo "$matches" | sed -n 's/^P|//p')"
    subs="$(echo "$matches" | sed -n 's/^S|//p')"
  fi
  printf '\33[2K\r'
  clear
  echo -en "${InvGreen} ${InvDkGray}${CWhite} "; padright "2.L Lookup Threat Indicator - $v" 136; echo -e "${CClear}"
  echo -e "${InvGreen} ${CClear}"
  echo -e "${InvGreen} ${CClear} Results from the feeds IOCMON has downloaded (the lists DNS watch, conntrack and Skynet use), the raw URLhaus/ThreatFox downloads, and${CClear}"
  echo -e "${InvGreen} ${CClear} IOCMON's own logs and settings. Feeds that are switched off, or have not downloaded yet, are not searched.${CClear}"
  echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"

  lookupsection "Feed Matches"
  if [ -n "$exact" ]; then
    feedcount="$(echo "$exact" | cut -d'|' -f2 | tr ',' '\n' | sort -u | grep -c .)"
    lookuprow "Result" "FOUND - listed by $feedcount feed(s): $(emailfeedname "$(echo "$exact" | cut -d'|' -f2 | tr ',' '\n' | sort -u | tr '\n' ',' | sed 's/,$//')")" "$CRed"
    echo "$exact" | while IFS= read -r m; do
      if [ "$kind" = "ip" ] && [ "${m%%|*}" != "$v" ]; then lookupfeedmatch "$m" "netblock containing $v"; else lookupfeedmatch "$m"; fi
    done
  else
    lookuprow "Result" "not listed in any loaded feed" "$CGreen"
  fi

  if [ "$kind" = "domain" ]; then
    lookupsection "Related Listings"
    if [ -n "$parents" ]; then
      echo "$parents" | while IFS= read -r m; do lookupfeedmatch "$m" "parent domain of $v"; done
    else
      lookuprow "Parent domains" "none listed"
    fi
    if [ -n "$subs" ]; then
      nsubs="$(echo "$subs" | grep -c .)"
      echo -e "${InvGreen} ${CClear}"
      lookuprow "Subdomains listed" "$nsubs$([ "$nsubs" -gt 20 ] && echo ", the first 20 shown")" "$CYellow"
      echo "$subs" | head -n 20 | while IFS='|' read -r e s f; do lookuprow "" "$e  ($(emailfeedname "$s"): $f)"; done
    else
      lookuprow "Subdomains listed" "none"
    fi
  fi

  lookupurlhausraw "$v"
  lookupthreatfoxraw "$v"
  lookuphistory "$v" "$kind"
  lookupexceptions "$kind" "$v"

  lookupsection "Lookup Links"
  if [ "$kind" = "ip" ]; then
    lookuprow "AlienVault OTX" "$(otxiplink "$v")"
    lookuprow "AbuseIPDB" "https://www.abuseipdb.com/check/$v"
  else
    lookuprow "AlienVault OTX" "https://otx.alienvault.com/indicator/domain/$v"
  fi
  lookuprow "URLhaus" "https://urlhaus.abuse.ch/host/$enc/"
  lookuprow "ThreatFox" "https://threatfox.abuse.ch/browse.php?search=ioc%3A$enc"

  lookupreputation "$v" "$kind"
  echo -e "${InvGreen} ${CClear}"
  echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
}

# -------------------------------------------------------------------------------------------------------------------------
# vlookupindicator is the Research - Lookup Threat Indicator screen: asks for an IP or domain and shows every feed finding for it

vlookupindicator()
{
  local entry norm
  while true; do
    [ "$exitallmenus" -eq 1 ] && break
    resolvefeedsroot
    clear
    echo -en "${InvGreen} ${InvDkGray}${CWhite} "; padright "2.L Research - Lookup Threat Indicator" 136; echo -e "${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Look up any IP address or domain in the threat feeds IOCMON has downloaded. The result shows every feed that lists it, with all the${CClear}"
    echo -e "${InvGreen} ${CClear} detail those feeds carry, listed parent domains and subdomains, IOCMON's own alerts on it, any exception list covering it, lookup links,${CClear}"
    echo -e "${InvGreen} ${CClear} and an optional AbuseIPDB check. A URL or a defanged entry such as hxxp://evil[.]com/path is reduced to its host. Feeds are IPv4 only.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    if [ -z "$feedsroot" ] || { [ ! -s "$feedsroot/ips.txt" ] && [ ! -s "$feedsroot/domains.txt" ] && [ ! -s "$feedsroot/qfeeds_ips.txt" ] && [ ! -s "$feedsroot/qfeeds_domains.txt" ]; }; then
      echo -e "${InvGreen} ${CClear} ${CYellow}No feed lists are available yet (the drive is not mounted, or no feed has downloaded). Use (F) on the main screen to refresh them.${CClear}"
    else
      echo -e "${InvGreen} ${CClear} Searching ${CGreen}$(cat "$feedsroot/ips.txt" "$feedsroot/qfeeds_ips.txt" 2>/dev/null | wc -l | tr -d ' ')${CClear} IP/netblock and ${CGreen}$(cat "$feedsroot/domains.txt" "$feedsroot/qfeeds_domains.txt" 2>/dev/null | wc -l | tr -d ' ')${CClear} domain entries, feeds last updated ${CGreen}$(feedsoldestfetch)${CClear} (oldest)."
    fi
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -r -p "Please enter any IP or domain to determine if it is present in the available feeds (e=Exit): " entry
    case "$entry" in
      [Ee]) break ;;
      [Ee]!) exitallmenus=1; break ;;
      "") continue ;;
    esac
    norm="$(lookupnormalize "$entry")"
    case "$norm" in
      ip\|*|domain\|*)
        lookupresults "${norm%%|*}" "${norm#*|}"
        echo ""
        read -r -p "Press Enter to look up another indicator, or e=Exit: " entry
        case "$entry" in [Ee]) break ;; [Ee]!) exitallmenus=1; break ;; esac ;;
      ipv6\|*)
        echo ""; echo -e "${CYellow}IOCMON's feeds hold IPv4 addresses only, so an IPv6 address can't be looked up.${CClear}"; sleep 3 ;;
      *)
        echo ""; echo -e "${CYellow}That doesn't look like an IPv4 address or a domain name.${CClear}"; sleep 3 ;;
    esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# vfeedsources is the Feed Sources, Reputation, API Keys and Lookups submenu: feed toggles, API keys and the AbuseIPDB reputation check.

vfeedsources()
{
  while true; do
    [ "$exitallmenus" -eq 1 ] && break
    clear
    echo -en "${InvGreen} ${InvDkGray}${CWhite} "; padright "2. Feed Sources, Reputation, API Keys and Lookups" 136; echo -e "${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Please choose from the various options below to toggle an IoC feed source on or off, or to set its API key. Feodo, Spamhaus and NetAPI${CClear}"
    echo -e "${InvGreen} ${CClear} need no key, and NetAPI's compromised-domain list gives DNS watch its coverage out of the box. URLhaus and ThreatFox each need a free${CClear}"
    echo -e "${InvGreen} ${CClear} abuse.ch Auth-Key (one key from auth.abuse.ch works for both) and Q-Feeds needs a token; each key field becomes active once its feed is${CClear}"
    echo -e "${InvGreen} ${CClear} switched on. The optional AbuseIPDB reputation check (items 12-17) looks up the public IP behind each conntrack, DNS, dropbear or httpd${CClear}"
    echo -e "${InvGreen} ${CClear} alert as it is raised, and adds its abuse score, report history, top report categories, country, ISP and usage type to the dashboard,${CClear}"
    echo -e "${InvGreen} ${CClear} the Reputation log ([U]), the IoC log and alert emails. Under Research, (L) looks up any IP or domain in the downloaded feeds and${CClear}"
    echo -e "${InvGreen} ${CClear} shows all they hold about it.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    urlhauskeydisp="<none - required for URLhaus>"
    [ -n "$urlhausapikey" ] && urlhauskeydisp="<set>"
    apikeydisp="<none - required for ThreatFox>"
    [ -n "$threatfoxapikey" ] && apikeydisp="<set>"
    qfkeydisp="<none - required for Q-Feeds>"
    [ -n "$qfeedsapikey" ] && qfkeydisp="<set>"
    aipdbkeydisp="<none - required for AbuseIPDB>"
    [ -n "$abuseipdbapikey" ] && aipdbkeydisp="<set>"
    resolvestateroot
    echo -e "${InvGreen} ${CClear} ${CWhite}Security Intelligence Feeds${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 1)${CClear} : "; padright "Feodo Tracker" 30; echo -e ": $(booleantoyesno "$enablefeodo")"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 2)${CClear} : "; padright "Spamhaus DROP/EDROP" 30; echo -e ": $(booleantoyesno "$enablespamhaus")"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 3)${CClear} : "; padright "NetAPI Compromised Sites" 30; echo -e ": $(booleantoyesno "$enablenetapi")"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 4)${CClear} : "; padright "URLhaus" 30; echo -e ": $(booleantoyesno "$enableurlhaus")$(feedkeycell "( 5)" "URLhaus API Key" "$urlhauskeydisp" "$enableurlhaus")"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 6)${CClear} : "; padright "ThreatFox" 30; echo -e ": $(booleantoyesno "$enablethreatfox")$(feedkeycell "( 7)" "ThreatFox API Key" "$apikeydisp" "$enablethreatfox")"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 8)${CClear} : "; padright "General Feed refresh (hours)" 30; echo -e ": ${CGreen}$feedupdatehrs${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 9)${CClear} : "; padright "Q-Feeds (OSINT IP/domain)" 30; echo -e ": $(booleantoyesno "$enableqfeeds")$(feedkeycell "(10)" "Q-Feeds API Key" "$qfkeydisp" "$enableqfeeds")"
    menurow "(11)" "Q-Feeds refresh (hours)" "${CGreen}$qfeedshrs${CClear}" 30 "$enableqfeeds"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} ${CWhite}Reputation Checks${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(12)${CClear} : "; padright "AbuseIPDB reputation check" 30; echo -e ": $(booleantoyesno "$enableabuseipdb")$(feedkeycell "(13)" "AbuseIPDB API Key" "$aipdbkeydisp" "$enableabuseipdb")"
    menurow "(14)" "  Cache lifetime (hours)" "${CGreen}$abuseipdbcachehrs${CClear}" 30 "$enableabuseipdb"
    menurow "(15)" "  Report age window (days)" "${CGreen}$abuseipdbmaxage${CClear}" 30 "$enableabuseipdb"
    menurow "(16)" "  Daily lookup ceiling" "${CGreen}$abuseipdbdailymax${CClear}" 30 "$enableabuseipdb"
    menurow "(17)" "  Max lookups per scan cycle" "${CGreen}$abuseipdbcyclemax${CClear}" 30 "$enableabuseipdb"
    menurow "  |-" "  Lookup(s) used today" "${CGreen}$(abuseipdbusedtoday) of ${abuseipdbdailymax}${CClear}" 30 "$enableabuseipdb"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} ${CWhite}Research${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( L)${CClear} : "; padright "Lookup Threat Indicator" 30; echo -e ": ${CGreen}Search the loaded feeds for any IP or domain${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}  | ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( e)${CClear} : Exit${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (1-17, L=Lookup, e=Exit): " selfeed
    case "$selfeed" in
      1) if [ "$enablefeodo" -eq 1 ]; then enablefeodo=0; else enablefeodo=1; fi; feedsaveconfig ;;
      2) if [ "$enablespamhaus" -eq 1 ]; then enablespamhaus=0; else enablespamhaus=1; fi; feedsaveconfig ;;
      3) if [ "$enablenetapi" -eq 1 ]; then enablenetapi=0; else enablenetapi=1; fi; feedsaveconfig ;;
      4) if [ "$enableurlhaus" -eq 1 ]; then enableurlhaus=0; else enableurlhaus=1; abusechkeyoffer urlhaus; fi; feedsaveconfig ;;
      5) [ "$enableurlhaus" -eq 1 ] && { echo ""; read -p "Enter URLhaus (abuse.ch) Auth-Key (blank to clear): " urlhausapikey
         if [ -z "$urlhausapikey" ]; then
           enableurlhaus=0
           echo ""
           echo -e "${CYellow}Key cleared - URLhaus has been switched off.${CClear}"; sleep 3
         fi
         feedsaveconfig; } ;;
      6) if [ "$enablethreatfox" -eq 1 ]; then enablethreatfox=0; else enablethreatfox=1; abusechkeyoffer threatfox; fi; feedsaveconfig ;;
      7) [ "$enablethreatfox" -eq 1 ] && { echo ""; read -p "Enter ThreatFox (abuse.ch) Auth-Key (blank to clear): " threatfoxapikey
         if [ -z "$threatfoxapikey" ]; then
           enablethreatfox=0
           echo ""
           echo -e "${CYellow}Key cleared - ThreatFox has been switched off.${CClear}"; sleep 3
         fi
         feedsaveconfig; } ;;
      8) echo ""; echo -e "Current: ${CGreen}${feedupdatehrs}${CClear}"
         read -p "New feed refresh interval in hours (>=1, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 1 && feedupdatehrs="$val" && feedsaveconfig; } ;;
      9) if [ "$enableqfeeds" -eq 1 ]; then enableqfeeds=0; qfeedsclearfiles; else enableqfeeds=1; fi
         feedsaveconfig ;;
      10) [ "$enableqfeeds" -eq 1 ] && { echo ""; read -p "Enter Q-Feeds API token (blank to clear): " qfeedsapikey
         if [ -z "$qfeedsapikey" ]; then
           enableqfeeds=0; qfeedsclearfiles
           echo ""
           echo -e "${CYellow}Token cleared - Q-Feeds has been switched off.${CClear}"; sleep 3
         fi
         feedsaveconfig; } ;;
      11) [ "$enableqfeeds" -eq 1 ] && { echo ""; echo -e "Current: ${CGreen}${qfeedshrs}${CClear}"
          read -p "New Q-Feeds refresh interval in hours (>=1, blank to keep current): " val
          [ -n "$val" ] && { validateint "$val" 1 && qfeedshrs="$val" && feedsaveconfig; }; } ;;
      12) if [ "$enableabuseipdb" -eq 1 ]; then enableabuseipdb=0; else enableabuseipdb=1; fi
          feedsaveconfig ;;
      13) [ "$enableabuseipdb" -eq 1 ] && { echo ""; read -p "Enter AbuseIPDB API key (blank to clear): " abuseipdbapikey
          if [ -z "$abuseipdbapikey" ]; then
            enableabuseipdb=0
            echo ""
            echo -e "${CYellow}Key cleared - the AbuseIPDB reputation check has been switched off.${CClear}"; sleep 3
          fi
          [ -n "$stateroot" ] && rm -f "$stateroot/abuseipdb_block"
          feedsaveconfig; } ;;
      14) [ "$enableabuseipdb" -eq 1 ] && { echo ""; echo -e "Current: ${CGreen}${abuseipdbcachehrs}${CClear}"
          read -p "Hours to reuse a cached AbuseIPDB result before looking that IP up again (>=1, blank to keep current): " val
          [ -n "$val" ] && { validateint "$val" 1 && abuseipdbcachehrs="$val" && feedsaveconfig; }; } ;;
      15) [ "$enableabuseipdb" -eq 1 ] && { echo ""; echo -e "Current: ${CGreen}${abuseipdbmaxage}${CClear}"
          read -p "Days of AbuseIPDB reports each lookup covers (1-365, blank to keep current): " val
          [ -n "$val" ] && { validateint "$val" 1 && [ "$val" -le 365 ] && abuseipdbmaxage="$val" && feedsaveconfig; }; } ;;
      16) [ "$enableabuseipdb" -eq 1 ] && { echo ""; echo -e "Current: ${CGreen}${abuseipdbdailymax}${CClear}"
          read -p "Most AbuseIPDB lookups per day (>=1, keep it below your plan's limit - free = 1000, blank to keep current): " val
          [ -n "$val" ] && { validateint "$val" 1 && abuseipdbdailymax="$val" && feedsaveconfig; }; } ;;
      17) [ "$enableabuseipdb" -eq 1 ] && { echo ""; echo -e "Current: ${CGreen}${abuseipdbcyclemax}${CClear}"
          read -p "Most AbuseIPDB lookups in a single scan cycle (>=1, blank to keep current): " val
          [ -n "$val" ] && { validateint "$val" 1 && abuseipdbcyclemax="$val" && feedsaveconfig; }; } ;;
      [Ll]) vlookupindicator ;;
      [Ee]) feedkeylessrevert; break ;;
      [Ee]!) feedkeylessrevert; exitallmenus=1; break ;;
      *) ;;
    esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# vlogs opens the activity log in the editor

vlogs()
{
  if [ ! -f "$logfile" ]; then
    touch "$logfile"
  fi
  openlogview "$logfile"
  renderdashboard
}

# -------------------------------------------------------------------------------------------------------------------------
# rotatelogfile moves $1 to $1.1 (older copies to .2 and so on, up to $logkeep) once it reaches $2 lines, silently

rotatelogfile()
{
  local file="$1" maxlines="$2" curr i

  [ "$maxlines" -gt 0 ] || return
  [ -f "$file" ] || return

  curr="$(wc -l < "$file" | tr -d ' ')"
  [ "$curr" -ge "$maxlines" ] || return
  i="$logkeep"
  rm -f "$file.$i"
  while [ "$i" -gt 1 ]; do
    [ -f "$file.$((i - 1))" ] && mv -f "$file.$((i - 1))" "$file.$i"
    i=$((i - 1))
  done
  mv -f "$file" "$file.1"
}

# -------------------------------------------------------------------------------------------------------------------------
# logall prints a log and its rotated copies, oldest line first

logall()
{
  local file="$1" i="$logkeep"

  while [ "$i" -ge 1 ]; do
    [ -f "$file.$i" ] && cat "$file.$i"
    i=$((i - 1))
  done
  [ -f "$file" ] && cat "$file"
  return 0
}

# -------------------------------------------------------------------------------------------------------------------------
# logtail prints a log's newest $2 lines, reaching into its newest rotated copy when the current file is shorter

logtail()
{
  { tail -n "$2" "$1.1" 2>/dev/null; tail -n "$2" "$1" 2>/dev/null; } | tail -n "$2"
}

# -------------------------------------------------------------------------------------------------------------------------
# openlogview opens a log in the editor, as one read-only /tmp copy with its rotated copies when it has any

openlogview()
{
  local file="$1" viewcopy="/tmp/iocmon_logview.$$"

  if [ -f "$file.1" ]; then
    logall "$file" > "$viewcopy"
    openeditor "$viewcopy"
    rm -f "$viewcopy"
  else
    openeditor "$file"
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# logremoverotated deletes a log's rotated copies

logremoverotated()
{
  local i="$logkeep"

  while [ "$i" -ge 1 ]; do
    rm -f "$1.$i"
    i=$((i - 1))
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# checklogrotate rotates the activity log once every 6 hours, right after the feed update check, if it has reached $logsize

checklogrotate()
{
  local nowepoch lastepoch

  nowepoch=$(date +%s)
  lastepoch="$(cat "$logtrimstamp" 2>/dev/null)"
  [ -z "$lastepoch" ] && lastepoch=0
  [ $((nowepoch - lastepoch)) -ge 21600 ] || return
  rotatelogfile "$logfile" "$logsize"
  echo "$nowepoch" > "$logtrimstamp"
}

# -------------------------------------------------------------------------------------------------------------------------
# resolvefeedsroot picks where feed data is written this cycle

resolvefeedsroot()
{
  checkdrivealive

  if [ -n "$extdrivelabel" ] && [ "$driveavailable" -eq 1 ]; then
    feedsroot="$iocmonroot/feeds"
    feedsdegraded=0
  elif [ -z "$extdrivelabel" ]; then
    feedsroot="$addonsdir/feeds-degraded"
    feedsdegraded=1
  else
    feedsroot=""
    feedsdegraded=1
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# fetchfeedsource does the fetch+cache half of the feed pipeline for one source

fetchfeedsource()
{
  local name="$1" url="$2" rawfile="$3" metafile="$4"
  local tmpfile="${rawfile}.tmp" curlrc

  if [ -f "$metafile" ]; then
    curl --silent --fail --retry 3 --connect-timeout 10 --max-time 180 -z "$metafile" -o "$tmpfile" "$url"
  else
    curl --silent --fail --retry 3 --connect-timeout 10 --max-time 180 -o "$tmpfile" "$url"
  fi
  curlrc=$?

  if [ "$curlrc" -ne 0 ]; then
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - ERROR: Unable to download $name feed ($url) - curl exit $curlrc." >> "$logfile"
    rm -f "$tmpfile"
    return 1
  fi

  if [ ! -s "$tmpfile" ]; then
    rm -f "$tmpfile"
    if [ -s "$rawfile" ]; then
      touch "$metafile"
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: $name feed unchanged since the last fetch ($(wc -l < "$rawfile" | tr -d ' ') lines kept)." >> "$logfile"
      return 0
    else
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - ERROR: $name feed returned no content and no prior cache exists." >> "$logfile"
      return 1
    fi
  fi

  mv "$tmpfile" "$rawfile"
  touch "$metafile"
  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: $name feed updated ($(wc -l < "$rawfile" | tr -d ' ') lines)." >> "$logfile"
  return 0
}

# -------------------------------------------------------------------------------------------------------------------------
# fetchthreatfox downloads ThreatFox's authenticated get_iocs JSON (an abuse.ch Auth-Key is required; jq is optional).

fetchthreatfox()
{
  local rawfile="$feedsroot/threatfox.raw" metafile="$feedsroot/meta/threatfox.meta"
  local modefile="$feedsroot/meta/threatfox.mode" tmpfile="$rawfile.tmp" curlrc

  if [ -z "$threatfoxapikey" ]; then
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: ThreatFox is enabled but no abuse.ch Auth-Key is set; skipping." >> "$logfile"
    return 2
  fi

  curl --silent --retry 2 --connect-timeout 5 --max-time 180 \
    -H "Auth-Key: $threatfoxapikey" -H "Content-Type: application/json" \
    -d '{"query":"get_iocs","days":3}' \
    -o "$tmpfile" "https://threatfox-api.abuse.ch/api/v1/"
  curlrc=$?

  if [ "$curlrc" -ne 0 ]; then
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - ERROR: Unable to download ThreatFox feed - curl exit $curlrc." >> "$logfile"
    rm -f "$tmpfile"
    return 1
  fi

  if [ ! -s "$tmpfile" ]; then
    rm -f "$tmpfile"
    if [ -s "$rawfile" ] && [ "$(cat "$modefile" 2>/dev/null)" = "api" ]; then
      touch "$metafile"
      return 0
    else
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - ERROR: ThreatFox feed returned no content and no prior cache exists." >> "$logfile"
      return 1
    fi
  fi

  if ! grep -q '"query_status"[[:space:]]*:[[:space:]]*"ok"' "$tmpfile"; then
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - ERROR: ThreatFox API returned an unexpected response (bad Auth-Key or rate limit): $(head -c 200 "$tmpfile" | tr -d '\r\n')" >> "$logfile"
    rm -f "$tmpfile"
    return 1
  fi

  mv "$tmpfile" "$rawfile"
  echo "api" > "$modefile"
  touch "$metafile"
  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: ThreatFox feed updated ($(grep -o '"ioc_type"' "$rawfile" | wc -l | tr -d ' ') IOC records)." >> "$logfile"
  return 0
}

# -------------------------------------------------------------------------------------------------------------------------
# fetchurlhaus downloads URLhaus's authenticated 30-day CSV export plus its recent-payloads JSON (malware file hashes).

fetchurlhaus()
{
  local rawfile="$feedsroot/urlhaus.raw" metafile="$feedsroot/meta/urlhaus.meta" tmpfile="$feedsroot/urlhaus.raw.tmp"
  local payfile="$feedsroot/urlhaus_payloads.raw" paytmp="$feedsroot/urlhaus_payloads.raw.tmp" code curlrc

  if [ -z "$urlhausapikey" ]; then
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: URLhaus is enabled but no abuse.ch Auth-Key is set; skipping." >> "$logfile"
    return 2
  fi

  if [ -f "$metafile" ] && grep -q '^"[0-9]' "$rawfile" 2>/dev/null; then
    code="$(printf 'url = "https://urlhaus-api.abuse.ch/v2/files/exports/%s/recent.csv"\n' "$urlhausapikey" | curl --silent --retry 3 --connect-timeout 10 --max-time 180 -K - -z "$metafile" -o "$tmpfile" -w '%{http_code}')"
  else
    code="$(printf 'url = "https://urlhaus-api.abuse.ch/v2/files/exports/%s/recent.csv"\n' "$urlhausapikey" | curl --silent --retry 3 --connect-timeout 10 --max-time 180 -K - -o "$tmpfile" -w '%{http_code}')"
  fi
  curlrc=$?

  if [ "$curlrc" -ne 0 ]; then
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - ERROR: Unable to download the URLhaus export - curl exit $curlrc." >> "$logfile"
    rm -f "$tmpfile"
    return 1
  fi

  case "$code" in
    304) rm -f "$tmpfile"; touch "$metafile"; urlhauslogstate="unchanged since the last fetch" ;;
    200)
      if [ "$(head -c 2 "$tmpfile")" = "PK" ] && which unzip >/dev/null 2>&1; then
        unzip -p "$tmpfile" > "${tmpfile}.csv" 2>/dev/null; mv "${tmpfile}.csv" "$tmpfile"
      fi
      if grep -q '^"[0-9]' "$tmpfile" 2>/dev/null; then
        mv "$tmpfile" "$rawfile"; touch "$metafile"; urlhauslogstate="updated"
      elif [ ! -s "$tmpfile" ] && grep -q '^"[0-9]' "$rawfile" 2>/dev/null; then
        rm -f "$tmpfile"; touch "$metafile"; urlhauslogstate="unchanged since the last fetch"
      else
        echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - ERROR: The URLhaus export was not in the expected CSV format: $(head -c 200 "$tmpfile" | tr -d '\r\n')" >> "$logfile"
        rm -f "$tmpfile"
        return 1
      fi ;;
    401|403)
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - ERROR: URLhaus rejected the Auth-Key (HTTP $code) - check it under Configuration Menu 2, item 5." >> "$logfile"
      rm -f "$tmpfile"
      return 1 ;;
    *)
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - ERROR: The URLhaus export returned HTTP ${code:-000}: $(head -c 200 "$tmpfile" 2>/dev/null | tr -d '\r\n')" >> "$logfile"
      rm -f "$tmpfile"
      return 1 ;;
  esac

  printf 'header = "Auth-Key: %s"\nurl = "https://urlhaus-api.abuse.ch/v1/payloads/recent/limit/1000/"\n' "$urlhausapikey" | curl --silent --retry 2 --connect-timeout 10 --max-time 180 -K - -o "$paytmp"
  if grep -q '"query_status"[[:space:]]*:[[:space:]]*"ok"' "$paytmp" 2>/dev/null; then
    mv "$paytmp" "$payfile"
  else
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: The URLhaus recent-payloads query failed; keeping the previous payload hash list: $(head -c 200 "$paytmp" 2>/dev/null | tr -d '\r\n')" >> "$logfile"
    rm -f "$paytmp"
  fi

  return 0
}

# -------------------------------------------------------------------------------------------------------------------------
# threatfoxtsv prints ThreatFox's get_iocs JSON ($1) as "ioc<TAB>type<TAB>malware<TAB>confidence<TAB>threat_type<TAB>tags" lines, via jq or awk.

threatfoxtsv()
{
  if which jq >/dev/null 2>&1; then
    jq -r 'if .query_status=="ok" then (.data[]? | [(.ioc // ""), (.ioc_type // ""), (.malware_printable // ""), (.confidence_level // ""), (.threat_type // ""), ((.tags // []) | join(" "))] | @tsv) else empty end' "$1" 2>/dev/null
  else
    awk -v RS='}' '
      function jv(k,  r) { if (match($0, "\""k"\"[[:space:]]*:[[:space:]]*\"[^\"]*\"")) { r = substr($0, RSTART, RLENGTH); sub(/^[^:]*:[[:space:]]*"/, "", r); sub(/"$/, "", r); gsub("\\\\/", "/", r); return r } return "" }
      function jn(k,  r) { if (match($0, "\""k"\"[[:space:]]*:[[:space:]]*[0-9]+")) { r = substr($0, RSTART, RLENGTH); sub(/^[^:]*:[[:space:]]*/, "", r); return r } return "" }
      function jt(  r) { if (match($0, /"tags"[[:space:]]*:[[:space:]]*\[[^]]*\]/)) { r = substr($0, RSTART, RLENGTH); sub(/^[^[]*\[/, "", r); sub(/\]$/, "", r); gsub(/"/, "", r); gsub(/[[:space:]]*,[[:space:]]*/, " ", r); gsub(/^[[:space:]]+|[[:space:]]+$/, "", r); return r } return "" }
      { v = jv("ioc"); t = jv("ioc_type"); if (v == "" || t == "") next; printf "%s\t%s\t%s\t%s\t%s\t%s\n", v, t, jv("malware_printable"), jn("confidence_level"), jv("threat_type"), jt() }
    ' "$1"
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# fetchqfeedlist downloads one Q-Feeds list ($1 feed, $2 dest, $3 ip|domain) with validation and an atomic swap.

fetchqfeedlist()
{
  local feed="$1" dest="$2" kind="$3" tmp="$2.tmp" code n

  code="$(printf 'user = "api_token:%s"\n' "$qfeedsapikey" | curl --silent --retry 1 --connect-timeout 10 --max-time 180 -K - -o "$tmp" -w '%{http_code}' "https://api.qfeeds.com/api.php?feed_type=${feed}&type=text&ipv6=0&download=0")"

  if [ "$code" != "200" ]; then
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - ERROR: Q-Feeds $feed download failed (HTTP ${code:-none}); keeping any previous list." >> "$logfile"
    rm -f "$tmp"
    return 1
  fi

  tr -d '\r' < "$tmp" | awk -v kind="$kind" '
    { l = tolower($0) }
    kind=="ip" && l ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/ { print l }
    kind=="domain" && l ~ /^[a-z0-9._-]+\.[a-z0-9-]+$/ { print l }
  ' > "${tmp}.ok"
  rm -f "$tmp"

  [ "$kind" = "ip" ] && dropreservedindicators "${tmp}.ok"

  n="$(wc -l < "${tmp}.ok" | tr -d ' ')"
  if [ "${n:-0}" -lt 1000 ]; then
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - ERROR: Q-Feeds $feed returned only ${n:-0} valid lines (expected thousands); keeping any previous list." >> "$logfile"
    rm -f "${tmp}.ok"
    return 1
  fi

  mv "${tmp}.ok" "$dest"
  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Q-Feeds $feed updated ($n entries)." >> "$logfile"
  return 0
}

# -------------------------------------------------------------------------------------------------------------------------
# fetchqfeeds refreshes both Q-Feeds lists on its own cadence; returns 0 ok, 1 failed, 2 skipped (not due or no token).

fetchqfeeds()
{
  local stamp="$feedsroot/meta/qfeeds.last" nowepoch lastepoch=0 rc=0

  if [ -z "$qfeedsapikey" ]; then
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: Q-Feeds is enabled but no API token is set; skipping." >> "$logfile"
    return 2
  fi

  nowepoch=$(date +%s)
  [ -f "$stamp" ] && lastepoch="$(cat "$stamp" 2>/dev/null)"
  [ -z "$lastepoch" ] && lastepoch=0
  if [ "$1" != "force" ] && [ -s "$feedsroot/qfeeds_ips.txt" ] && [ $((nowepoch - lastepoch)) -lt $((qfeedshrs * 3600)) ]; then
    return 2
  fi

  inlinestatus "Q-Feeds: fetching malware IP list"
  fetchqfeedlist malware_ip "$feedsroot/qfeeds_ips.txt" ip || rc=1
  inlinestatus "Q-Feeds: fetching malware domain list (rate-limit pause)"
  sleep 11
  fetchqfeedlist malware_domains "$feedsroot/qfeeds_domains.txt" domain || rc=1

  [ "$rc" -eq 0 ] && echo "$nowepoch" > "$stamp"
  return "$rc"
}

# -------------------------------------------------------------------------------------------------------------------------
# qfeedsclearfiles deletes the downloaded Q-Feeds lists and their refresh stamp.

qfeedsclearfiles()
{
  resolvefeedsroot
  [ -n "$feedsroot" ] && rm -f "$feedsroot/qfeeds_ips.txt" "$feedsroot/qfeeds_domains.txt" "$feedsroot/meta/qfeeds.last"
}

# -------------------------------------------------------------------------------------------------------------------------
# qfeedscount echoes the total Q-Feeds indicator lines currently loaded (0 when disabled).

qfeedscount()
{
  local f n=0

  if [ "$enableqfeeds" -eq 1 ] && [ -n "$feedsroot" ]; then
    for f in "$feedsroot/qfeeds_ips.txt" "$feedsroot/qfeeds_domains.txt"; do
      [ -s "$f" ] && n=$((n + $(wc -l < "$f" | tr -d ' ')))
    done
  fi
  echo "$n"
}

# -------------------------------------------------------------------------------------------------------------------------
# dropreservedindicators removes list $1 lines whose indicator overlaps a loopback, private, CGNAT, multicast or other reserved range

dropreservedindicators()
{
  local f="$1" kept="$1.routable" result
  [ -s "$f" ] || return 0
  : > "$kept"
  result="$(awk -F'|' -v kept="$kept" '
    function toint(ip,  a) { split(ip, a, "."); return (a[1]*16777216)+(a[2]*65536)+(a[3]*256)+a[4] }
    function reserved(ind,  p, o, m, k, d, v) {
      if (index(ind, ":")) return (ind ~ /^::1?(\/|$)|^f[cd][0-9a-f][0-9a-f]:|^fe[89ab][0-9a-f]:|^ff[0-9a-f][0-9a-f]:/)
      if (ind !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/) return 0
      split(ind, p, "/")
      m = (p[2] == "" ? 32 : p[2] + 0)
      if (m > 32) return 0
      split(p[1], o, ".")
      # Most addresses are ruled out here, which matters on a list of 250k lines.
      if (m >= 8 && !((o[1] + 0) in firstoctet)) return 0
      v = (o[1]*16777216)+(o[2]*65536)+(o[3]*256)+o[4]
      for (k = 1; k <= rn; k++) {
        d = 2 ^ (32 - (m < rmask[k] ? m : rmask[k]))
        if (int(v / d) == int(rnet[k] / d)) return 1
      }
      return 0
    }
    BEGIN {
      rn = split("0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4", r, " ")
      for (k = 1; k <= rn; k++) {
        split(r[k], q, "/"); rnet[k] = toint(q[1]); rmask[k] = q[2] + 0
        split(q[1], a, "."); last = a[1] + (rmask[k] < 8 ? 2 ^ (8 - rmask[k]) - 1 : 0)
        for (i = a[1] + 0; i <= last; i++) firstoctet[i] = 1
      }
    }
    {
      if (reserved(tolower($1))) {
        n++
        if (n <= 5) shown = shown (shown == "" ? "" : ", ") $1 ($2 == "" ? "" : " (" $2 ")")
        next
      }
      print > kept
    }
    END { print n + 0 "|" shown (n > 5 ? ", ..." : "") }
  ' "$f")" || { rm -f "$kept"; return 0; }
  mv "$kept" "$f"
  [ "${result%%|*}" -gt 0 ] && echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Dropped ${result%%|*} non-routable IP indicator(s) from the feeds: ${result#*|}." >> "$logfile"
  return 0
}

# -------------------------------------------------------------------------------------------------------------------------
# dedupindicators collapses duplicate "indicator|source|family" lines in $1 into one line per indicator, comma-joining sources/families.

dedupindicators()
{
  local f="$1"
  [ -s "$f" ] || return
  awk -F'|' '
    {
      ind = $1
      if (!(ind in seen)) { order[++n] = ind; seen[ind] = 1 }
      if (index(","srcs[ind]",", ","$2",") == 0) { srcs[ind] = (srcs[ind]=="" ? $2 : srcs[ind]","$2) }
      if (index(","fams[ind]",", ","$3",") == 0) { fams[ind] = (fams[ind]=="" ? $3 : fams[ind]","$3) }
    }
    END { for (i=1; i<=n; i++) { ind = order[i]; print ind"|"srcs[ind]"|"fams[ind] } }
  ' "$f" > "${f}.dedup" && mv "${f}.dedup" "$f"
}

# -------------------------------------------------------------------------------------------------------------------------
# normalizefeeds is the normalize-swap part of the process

normalizefeeds()
{
  local tmpips="$feedsroot/ips.txt.tmp" tmpdomains="$feedsroot/domains.txt.tmp" tmphashes="$feedsroot/hashes.txt.tmp"
  threatfoxskippedcount=0; urlhauskeptcount=0; urlhauspayloadcount=0

  : > "$tmpips"
  : > "$tmpdomains"
  : > "$tmphashes"

  if [ "$enablefeodo" -eq 1 ] && [ -s "$feedsroot/feodo.raw" ]; then
    awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/ {print $1"|feodo|botnet-c2"}' "$feedsroot/feodo.raw" >> "$tmpips"
  fi

  if [ "$feedsdegraded" -eq 0 ]; then
    if [ "$enablespamhaus" -eq 1 ] && [ -s "$feedsroot/spamhaus_drop.raw" ]; then
      awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/ {print $1"|spamhaus-drop|netblock"}' "$feedsroot/spamhaus_drop.raw" >> "$tmpips"
    fi
    if [ "$enablespamhaus" -eq 1 ] && [ -s "$feedsroot/spamhaus_edrop.raw" ]; then
      awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/ {print $1"|spamhaus-edrop|netblock"}' "$feedsroot/spamhaus_edrop.raw" >> "$tmpips"
    fi

    if [ "$enablenetapi" -eq 1 ] && [ -s "$feedsroot/netapi_ips.raw" ]; then
      awk '{ sub(/\r$/, "") } /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/ {print $0"|netapi|compromised-ip"}' "$feedsroot/netapi_ips.raw" >> "$tmpips"
    fi
    if [ "$enablenetapi" -eq 1 ] && [ -s "$feedsroot/netapi_domains.raw" ]; then
      awk '{ sub(/\r$/, "") } $1 == "0.0.0.0" && NF == 2 && $2 ~ /^[A-Za-z0-9_.-]+\.[A-Za-z0-9-]+$/ {print tolower($2)"|netapi|compromised-site"}' "$feedsroot/netapi_domains.raw" >> "$tmpdomains"
    fi

    if [ "$enableurlhaus" -eq 1 ] && grep -q '^"[0-9]' "$feedsroot/urlhaus.raw" 2>/dev/null; then
      inlinestatus "Normalizing URLhaus"
      urlhauskeptcount="$(awk -v ipsout="$tmpips" -v domainsout="$tmpdomains" -v today="$(date +'%Y %m %d')" '
        function dn(y, m, d,  era, yoe, doy) { if (m <= 2) y--; era = int((y >= 0 ? y : y - 399) / 400); yoe = y - era * 400; doy = int((153 * (m > 2 ? m - 3 : m + 9) + 2) / 5) + d - 1; return era * 146097 + yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy }
        BEGIN { split(today, t, " "); now = dn(t[1] + 0, t[2] + 0, t[3] + 0) }
        /^"[0-9]/ {
          line = $0; sub(/\r$/, "", line); sub(/^"/, "", line); sub(/"$/, "", line)
          if (split(line, f, /","/) < 7) next
          if (f[4] != "online" && now - dn(substr(f[2], 1, 4) + 0, substr(f[2], 6, 2) + 0, substr(f[2], 9, 2) + 0) > 2) next
          host = f[3]; sub(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, "", host); sub(/[\/?#].*$/, "", host); sub(/^.*@/, "", host)
          if (host ~ /^\[/) next
          sub(/:[0-9]+$/, "", host); host = tolower(host)
          if (host == "") next
          if (!(host in cnt)) order[++hn] = host
          cnt[host]++
          if (f[6] != "" && index(" "thr[host]" ", " "f[6]" ") == 0) thr[host] = (thr[host] == "" ? f[6] : thr[host]" "f[6])
          nt = split(f[7], tg, ",")
          for (i = 1; i <= nt; i++) { g = tg[i]; gsub(/^ +| +$|\|/, "", g); if (g != "" && g != "None" && ntag[host] < 6 && index(" "tags[host]" ", " "g" ") == 0) { tags[host] = (tags[host] == "" ? g : tags[host]" "g); ntag[host]++ } }
        }
        END {
          for (i = 1; i <= hn; i++) {
            h = order[i]; fam = (thr[h] != "" ? thr[h] : "malware_download")"; "cnt[h]" URL(s)"
            if (tags[h] != "") fam = fam"; tags: "tags[h]
            if (h ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print h"|urlhaus|"fam >> ipsout; else print h"|urlhaus|"fam >> domainsout
          }
          print hn + 0
        }' "$feedsroot/urlhaus.raw")"
    fi

    if [ "$enableurlhaus" -eq 1 ] && [ -s "$feedsroot/urlhaus_payloads.raw" ]; then
      urlhauspayloadcount="$(awk -v RS='}' -v hashesout="$tmphashes" '
        function jv(k,  r) { if (match($0, "\""k"\"[[:space:]]*:[[:space:]]*\"[^\"]*\"")) { r = substr($0, RSTART, RLENGTH); sub(/^[^:]*:[[:space:]]*"/, "", r); sub(/"$/, "", r); return r } return "" }
        {
          sha = jv("sha256_hash"); if (sha == "") next
          md5 = jv("md5_hash"); sig = jv("signature"); ft = jv("file_type")
          fam = (sig != "" ? sig : "malware payload"); if (ft != "") fam = fam" ("ft" file)"; gsub(/\|/, "/", fam)
          print tolower(sha)"|urlhaus|"fam >> hashesout; if (md5 != "") print tolower(md5)"|urlhaus|"fam >> hashesout
          n++
        }
        END { print n + 0 }' "$feedsroot/urlhaus_payloads.raw")"
    fi

    if [ -n "$urlhauslogstate" ]; then
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: URLhaus feed $urlhauslogstate ($(grep -c '^"[0-9]' "$feedsroot/urlhaus.raw" 2>/dev/null | tr -d ' ') URL records -> ${urlhauskeptcount:-0} active host(s), online or added in the last 2 days; ${urlhauspayloadcount:-0} payload(s))." >> "$logfile"
      urlhauslogstate=""
    fi

    if [ "$enablethreatfox" -eq 1 ] && [ -s "$feedsroot/threatfox.raw" ] && [ "$(cat "$feedsroot/meta/threatfox.mode" 2>/dev/null)" = "api" ]; then
      inlinestatus "Normalizing ThreatFox"
      threatfoxskippedcount="$(threatfoxtsv "$feedsroot/threatfox.raw" | \
        awk -F'\t' -v ipsout="$tmpips" -v domainsout="$tmpdomains" -v hashesout="$tmphashes" '
          {
            val = $1; typ = $2; mal = $3; conf = $4; tt = $5; tags = $6
            if (val == "" || typ == "") next
            extra = tt
            if (conf != "") extra = (extra != "" ? extra"; " : "")"confidence: "conf
            if (tags != "") extra = (extra != "" ? extra"; " : "")"tags: "tags
            if (typ == "ip:port") { sub(/:[0-9]+$/, "", val); out = ipsout; base = "ip" }
            else if (typ == "domain") { out = domainsout; base = "domain" }
            else if (typ == "url") {
              sub(/^[A-Za-z]+:\/\//, "", val); sub(/[\/?#].*$/, "", val); sub(/:[0-9]+$/, "", val)
              if (val == "") { skip++; next }
              out = (val ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) ? ipsout : domainsout; base = "url-host"
            }
            else if (typ ~ /_hash$/) { out = hashesout; base = typ }
            else { skip++; next }
            fam = (mal != "" ? mal : base); if (extra != "") fam = fam" ("extra")"; gsub(/\|/, "/", fam)
            print val"|threatfox|"fam >> out
          }
          END { print skip+0 }')"
    fi
  fi

  dropreservedindicators "$tmpips"

  if [ -s "$tmpips" ]; then
    inlinestatus "Deduplicating IP/CIDR indicators"
    dedupindicators "$tmpips"
    mv "$tmpips" "$feedsroot/ips.txt"
  else
    rm -f "$tmpips"
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: Feed normalization produced zero IP indicators; leaving the previous ips.txt in place." >> "$logfile"
  fi

  if [ -s "$tmpdomains" ]; then
    inlinestatus "Deduplicating domain indicators"
    dedupindicators "$tmpdomains"
    mv "$tmpdomains" "$feedsroot/domains.txt"
  else
    rm -f "$tmpdomains"
    : > "$feedsroot/domains.txt"
  fi

  if [ -s "$tmphashes" ]; then
    inlinestatus "Deduplicating hash indicators"
    dedupindicators "$tmphashes"
    mv "$tmphashes" "$feedsroot/hashes.txt"
  else
    rm -f "$tmphashes"
    [ -f "$feedsroot/hashes.txt" ] || : > "$feedsroot/hashes.txt"
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# resolveskynetloc finds Skynet's own storage directory the same way firewall.sh locates it - parsing skynetloc= off its firewall-start hook.

resolveskynetloc()
{
  skynetstoragepath=""
  [ -f /jffs/scripts/firewall-start ] || return
  skynetstoragepath="$(awk '$1 == "sh" && $2 == "/jffs/scripts/firewall" && $3 == "start" {
    for (i = 4; i <= NF; i++) if ($i ~ /^skynetloc=/) { sub(/^skynetloc=/, "", $i); print $i; exit }
  }' /jffs/scripts/firewall-start 2>/dev/null)"
}

# -------------------------------------------------------------------------------------------------------------------------
# skynetinstalled succeeds only when Skynet's firewall.sh and its own rule registry are both actually present.

skynetinstalled()
{
  resolveskynetloc
  [ -x /jffs/scripts/firewall ] && [ -n "$skynetstoragepath" ] && [ -f "$skynetstoragepath/skynet.rules" ]
}

# -------------------------------------------------------------------------------------------------------------------------
# skynetimportids echoes every Skynet import rule ID tagged with our "IOCMON" comment - same registry match Reference/skynet-importcheck.sh uses.

skynetimportids()
{
  resolveskynetloc
  [ -n "$skynetstoragepath" ] && [ -f "$skynetstoragepath/skynet.rules" ] || return
  awk -F '\t' '
    $1 == "R2" && $3 == "ban" && $4 == "import" {
      comment = substr($6, 2)
      if (index(tolower(comment), "iocmon")) print $2
    }' "$skynetstoragepath/skynet.rules"
}

# -------------------------------------------------------------------------------------------------------------------------
# removeskynetimports deletes every existing IOCMON-tagged Skynet import rule, if any - always run before a fresh import, and on disable.

removeskynetimports()
{
  local id removed=0
  skynetremovedcount=0
  for id in ${1-$(skynetimportids)}; do
    if sh /jffs/scripts/firewall rules remove "$id" >/dev/null 2>&1; then
      removed=$((removed + 1))
    else
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: Failed to remove Skynet import rule $id." >> "$logfile"
    fi
  done
  skynetremovedcount="$removed"
  [ "$removed" -gt 0 ] && echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Removed $removed existing IOCMON-tagged Skynet import rule(s)." >> "$logfile"
}

# -------------------------------------------------------------------------------------------------------------------------
# buildskynetimportfile writes a plain, single-column IPv4/CIDR list to $1 from the current feed indicators, minus anything on the IP/CIDR Exceptions list.

buildskynetimportfile()
{
  local out="$1"

  skynetprogress 2 6 "Building combined indicator list"
  : > "$out"
  [ -s "$feedsroot/ips.txt" ] && cut -d'|' -f1 "$feedsroot/ips.txt" >> "$out"
  [ "$skynetimportqfeeds" -eq 1 ] && [ -s "$feedsroot/qfeeds_ips.txt" ] && cat "$feedsroot/qfeeds_ips.txt" >> "$out"

  skynetprogress 3 6 "Deduplicating indicator list"
  sort -u -o "$out" "$out"

  [ -z "$ipexceptions" ] && return

  skynetprogress 4 6 "Filtering IP/CIDR exceptions"
  awk -v exc="$ipexceptions" '
    function toint(ip,  a) { split(ip, a, "."); return (a[1]*16777216)+(a[2]*65536)+(a[3]*256)+a[4] }
    function fromint(n) { return int(n / 16777216) "." (int(n / 65536) % 256) "." (int(n / 256) % 256) "." (n % 256) }
    function keep(net, m, k,    d) {
      for (; k <= excn; k++) {
        if (!(k in excnet)) continue
        d = 2 ^ (32 - (excmask[k] < m ? excmask[k] : m))
        if (int(net / d) != int(excnet[k] / d)) continue
        if (excmask[k] <= m) return
        d = 2 ^ (31 - m)
        net = int(net / (2 * d)) * (2 * d)
        keep(net, m + 1, k + 0)
        keep(net + d, m + 1, k + 0)
        return
      }
      print (m == 32 ? fromint(net) : fromint(net) "/" m)
    }
    BEGIN {
      excn = split(exc, ea, " ")
      for (k = 1; k <= excn; k++) {
        if (ea[k] == "") continue
        split(ea[k], pp, "/")
        mask = (pp[2] == "" ? 32 : pp[2] + 0)
        if (mask < 0 || mask > 32) continue
        excnet[k] = toint(pp[1]); excmask[k] = mask
      }
    }
    { split($0, pp, "/"); keep(toint(pp[1]), (pp[2] == "" ? 32 : pp[2] + 0), 1) }
  ' "$out" > "${out}.tmp"
  mv "${out}.tmp" "$out"
}

# -------------------------------------------------------------------------------------------------------------------------
# syncskynetimport pushes the current IPv4 feed set into Skynet's ban list, tagged "IOCMON" - only when it actually changed since last time.

syncskynetimport()
{
  local force="$1"

  [ "$enableskynetimport" -eq 1 ] || return 2

  skynetprogress 1 6 "Checking Skynet installation"
  if ! skynetinstalled; then
    if [ "$skynetmissinglogged" -ne 1 ]; then
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: Skynet integration is enabled but Skynet was not detected - import skipped." >> "$logfile"
      skynetmissinglogged=1
    fi
    return 2
  fi
  skynetmissinglogged=0

  local importfile="/tmp/iocmon_skynet_import.$$" hashfile="$feedsroot/meta/skynet_import.hash" newhash oldhash entrycount

  buildskynetimportfile "$importfile"
  entrycount="$(wc -l < "$importfile" | tr -d ' ')"
  newhash="$(filecontenthash "$importfile")"
  oldhash=""
  [ -f "$hashfile" ] && oldhash="$(cat "$hashfile" 2>/dev/null)"

  if [ "$force" != "force" ] && [ "$newhash" = "$oldhash" ]; then
    rm -f "$importfile"
    return 1
  fi

  if [ "$entrycount" -eq 0 ]; then
    skynetprogress 5 6 "Removing previous IOCMON-tagged rule(s)"
    removeskynetimports
    rm -f "$importfile"
    echo "$newhash" > "$hashfile"
    return 1
  fi

  local previmports
  previmports="$(skynetimportids)"

  skynetprogress 5 6 "Importing $entrycount entries into Skynet"
  local importattempt=0 importrc=1 importoutput=""
  while [ "$importattempt" -lt 3 ]; do
    [ "$importattempt" -gt 0 ] && sleep $((importattempt * 3))
    importoutput="$(sh /jffs/scripts/firewall import blacklist "$importfile" "IOCMON Threat Feed Import ($entrycount entries)" 2>&1)"
    importrc=$?
    [ "$importrc" -eq 0 ] && break
    importattempt=$((importattempt + 1))
  done

  if [ "$importrc" -eq 0 ]; then
    echo "$newhash" > "$hashfile"
    rm -f "$importfile"
    # Only once a new rule exists: a failed import keeps the old bans in force.
    if [ "$(skynetimportids)" != "$previmports" ]; then
      skynetprogress 6 6 "Removing superseded IOCMON-tagged rule(s)"
      removeskynetimports "$previmports"
    fi
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Imported $entrycount IPv4 indicator(s) into Skynet's ban list, tagged IOCMON." >> "$logfile"
    skynetimportcount="$entrycount"
    return 0
  else
    rm -f "$importfile"
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: Skynet import failed after 3 attempt(s) - will retry next refresh cycle. firewall output: $(echo "$importoutput" | tr '\n' ' ' | cut -c1-300)" >> "$logfile"
    return 3
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# updatefeeds is the feed-manager orchestrator: fetch each enabled source, then normalize.

updatefeeds()
{
  local okcount=0 failcount=0 qrc skrc

  mkdir -m 755 -p "$feedsroot/meta"

  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Starting IoC feed refresh cycle." >> "$logfile"

  if [ "$enablefeodo" -eq 1 ]; then
    inlinestatus "Feodo Tracker: fetching"
    if fetchfeedsource "Feodo Tracker" "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt" "$feedsroot/feodo.raw" "$feedsroot/meta/feodo.meta"; then
      okcount=$((okcount+1))
      echo -e "\33[2K\r  ${CGreen}*${CClear} Feodo Tracker: fetched ${CGreen}$(wc -l < "$feedsroot/feodo.raw" 2>/dev/null | tr -d ' ')${CClear} indicators"
    else
      failcount=$((failcount+1))
      echo -e "\33[2K\r  ${CRed}*${CClear} Feodo Tracker: fetch failed (see log)"
    fi
  fi

  if [ "$feedsdegraded" -eq 0 ]; then
    if [ "$enablespamhaus" -eq 1 ]; then
      inlinestatus "Spamhaus DROP: fetching"
      if fetchfeedsource "Spamhaus DROP" "https://www.spamhaus.org/drop/drop.txt" "$feedsroot/spamhaus_drop.raw" "$feedsroot/meta/spamhaus_drop.meta"; then
        okcount=$((okcount+1))
        echo -e "\33[2K\r  ${CGreen}*${CClear} Spamhaus DROP: fetched ${CGreen}$(wc -l < "$feedsroot/spamhaus_drop.raw" 2>/dev/null | tr -d ' ')${CClear} netblocks"
      else
        failcount=$((failcount+1))
        echo -e "\33[2K\r  ${CRed}*${CClear} Spamhaus DROP: fetch failed (see log)"
      fi
      inlinestatus "Spamhaus EDROP: fetching"
      if fetchfeedsource "Spamhaus EDROP" "https://www.spamhaus.org/drop/edrop.txt" "$feedsroot/spamhaus_edrop.raw" "$feedsroot/meta/spamhaus_edrop.meta"; then
        okcount=$((okcount+1))
        echo -e "\33[2K\r  ${CGreen}*${CClear} Spamhaus EDROP: fetched ${CGreen}$(wc -l < "$feedsroot/spamhaus_edrop.raw" 2>/dev/null | tr -d ' ')${CClear} netblocks"
      else
        failcount=$((failcount+1))
        echo -e "\33[2K\r  ${CRed}*${CClear} Spamhaus EDROP: fetch failed (see log)"
      fi
    fi

    if [ "$enablenetapi" -eq 1 ]; then
      inlinestatus "NetAPI compromised IPs: fetching"
      if fetchfeedsource "NetAPI compromised IP" "https://netapi.com/api2/?method=compromised&dataset_type=ip" "$feedsroot/netapi_ips.raw" "$feedsroot/meta/netapi_ips.meta"; then
        okcount=$((okcount+1))
        echo -e "\33[2K\r  ${CGreen}*${CClear} NetAPI compromised IPs: fetched ${CGreen}$(grep -cE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' "$feedsroot/netapi_ips.raw" 2>/dev/null)${CClear} IPv4 address(es)/netblock(s)"
      else
        failcount=$((failcount+1))
        echo -e "\33[2K\r  ${CRed}*${CClear} NetAPI compromised IPs: fetch failed (see log)"
      fi
      inlinestatus "NetAPI compromised sites: fetching"
      if fetchfeedsource "NetAPI compromised domain" "https://netapi.com/api2/?method=compromised&dataset_type=url&format=hosts" "$feedsroot/netapi_domains.raw" "$feedsroot/meta/netapi_domains.meta"; then
        okcount=$((okcount+1))
        echo -e "\33[2K\r  ${CGreen}*${CClear} NetAPI compromised sites: fetched ${CGreen}$(grep -c '^0\.0\.0\.0 ' "$feedsroot/netapi_domains.raw" 2>/dev/null)${CClear} domain(s)"
      else
        failcount=$((failcount+1))
        echo -e "\33[2K\r  ${CRed}*${CClear} NetAPI compromised sites: fetch failed (see log)"
      fi
    fi

    if [ "$enableurlhaus" -eq 1 ]; then
      inlinestatus "URLhaus: fetching"
      fetchurlhaus; urc=$?
      case "$urc" in
        0) okcount=$((okcount+1)); echo -e "\33[2K\r  ${CGreen}*${CClear} URLhaus: fetched ${CGreen}$(grep -c '^"[0-9]' "$feedsroot/urlhaus.raw" 2>/dev/null)${CClear} malware URL record(s) and ${CGreen}$(grep -o '"sha256_hash"' "$feedsroot/urlhaus_payloads.raw" 2>/dev/null | wc -l | tr -d ' ')${CClear} payload record(s)" ;;
        2) echo -e "\33[2K\r  ${CYellow}*${CClear} URLhaus: skipped (no abuse.ch Auth-Key set - Configuration Menu 2, item 5)" ;;
        *) failcount=$((failcount+1)); echo -e "\33[2K\r  ${CRed}*${CClear} URLhaus: fetch failed (see log)" ;;
      esac
    fi

    if [ "$enablethreatfox" -eq 1 ]; then
      inlinestatus "ThreatFox: fetching"
      fetchthreatfox; trc=$?
      case "$trc" in
        0) okcount=$((okcount+1)); echo -e "\33[2K\r  ${CGreen}*${CClear} ThreatFox: fetched ${CGreen}$(grep -o '"ioc_type"' "$feedsroot/threatfox.raw" 2>/dev/null | wc -l | tr -d ' ')${CClear} IOC records" ;;
        2) echo -e "\33[2K\r  ${CYellow}*${CClear} ThreatFox: skipped (no abuse.ch Auth-Key set - Configuration Menu 2, item 7)" ;;
        *) failcount=$((failcount+1)); echo -e "\33[2K\r  ${CRed}*${CClear} ThreatFox: fetch failed (see log)" ;;
      esac
    fi

    if [ "$enableqfeeds" -eq 1 ]; then
      inlinestatus "Q-Feeds: fetching"
      fetchqfeeds "$1"; qrc=$?
      case "$qrc" in
        0) okcount=$((okcount+1)); echo -e "\33[2K\r  ${CGreen}*${CClear} Q-Feeds: fetched ${CGreen}$(qfeedscount)${CClear} OSINT IP/domain indicators" ;;
        2) echo -e "\33[2K\r  ${CGreen}*${CClear} Q-Feeds: skipped (refreshed within the last ${qfeedshrs}h, or no token set)" ;;
        *) failcount=$((failcount+1)); echo -e "\33[2K\r  ${CRed}*${CClear} Q-Feeds: fetch failed (see log)" ;;
      esac
    fi
  fi

  inlinestatus "Normalizing & deduplicating feed data"
  normalizefeeds

  if [ "$enableskynetimport" -eq 1 ]; then
    syncskynetimport; skrc=$?
    case "$skrc" in
      0) echo -e "\33[2K\r  ${CGreen}*${CClear} Skynet import: pushed ${CGreen}${skynetimportcount:-0}${CClear} IPv4 indicator(s), tagged IOCMON" ;;
      1) echo -e "\33[2K\r  ${CGreen}*${CClear} Skynet import: unchanged, skipped" ;;
      2) echo -e "\33[2K\r  ${CGreen}*${CClear} Skynet import: Skynet not detected, skipped" ;;
      *) failcount=$((failcount+1)); echo -e "\33[2K\r  ${CRed}*${CClear} Skynet import: failed (see log)" ;;
    esac
  fi

  local ipscount domainscount hashescount qfeedstotal
  ipscount="$(wc -l < "$feedsroot/ips.txt" 2>/dev/null | tr -d ' ')"; ipscount="${ipscount:-0}"
  domainscount="$(wc -l < "$feedsroot/domains.txt" 2>/dev/null | tr -d ' ')"; domainscount="${domainscount:-0}"
  hashescount="$(wc -l < "$feedsroot/hashes.txt" 2>/dev/null | tr -d ' ')"; hashescount="${hashescount:-0}"
  qfeedstotal="$(qfeedscount)"

  echo -e "\33[2K\r  ${CGreen}*${CClear} Normalized into ${CGreen}$((ipscount + domainscount + hashescount))${CClear} deduped core-feed indicator(s): ${CGreen}${ipscount}${CClear} IP/CIDR, ${CGreen}${domainscount}${CClear} domain(s), ${CGreen}${hashescount}${CClear} hash(es) (${CGreen}${okcount}${CClear} sources ok, ${CRed}${failcount}${CClear} failed)"
  if [ "$qfeedstotal" -gt 0 ]; then
    echo -e "  ${CGreen}*${CClear} Plus ${CGreen}${qfeedstotal}${CClear} Q-Feeds indicator(s) kept separately (not deduped) - ${CGreen}$((ipscount + domainscount + hashescount + qfeedstotal))${CClear} total indicator(s) active for conntrack/DNS matching and Skynet import"
  fi
  if [ "${urlhauskeptcount:-0}" -gt 0 ] || [ "${urlhauspayloadcount:-0}" -gt 0 ]; then
    echo -e "  ${CGreen}*${CClear} URLhaus: ${CGreen}${urlhauskeptcount:-0}${CClear} host(s) kept (online, or added in the last 2 days) and ${CGreen}${urlhauspayloadcount:-0}${CClear} payload hash pair(s)"
  fi
  if [ "${threatfoxskippedcount:-0}" -gt 0 ]; then
    echo -e "  ${CYellow}*${CClear} ThreatFox: ${CYellow}${threatfoxskippedcount}${CClear} raw record(s) skipped (unsupported indicator type, e.g. ja3/tag-only entries)"
  fi
  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: IoC feed refresh cycle complete ($okcount ok, $failcount failed)." >> "$logfile"
  feedokcount="$okcount"; feedfailcount="$failcount"
}

# -------------------------------------------------------------------------------------------------------------------------
# feedslock/feedsunlock stop the main loop, cron, the (F) hotkey and the web button refreshing feeds at the same time

feedslock()
{
  local lockpid
  if [ -f "$feedslockfile" ]; then
    lockpid="$(cat "$feedslockfile" 2>/dev/null)"
    if [ -n "$lockpid" ] && [ "$lockpid" != "$$" ] && iocmonpid "$lockpid"; then
      return 1
    fi
  fi
  echo "$$" > "$feedslockfile"
  return 0
}

feedsunlock()
{
  rm -f "$feedslockfile"
}

# -------------------------------------------------------------------------------------------------------------------------
# checkfeedupdate is called every main-loop tick

checkfeedupdate()
{
  resolvefeedsroot

  if [ -z "$feedsroot" ]; then
    return
  fi

  mkdir -m 755 -p "$feedsroot/meta"

  local stampfile="$feedsroot/meta/.last_update" nowepoch lastepoch duesec

  nowepoch=$(date +%s)
  lastepoch=0
  [ -f "$stampfile" ] && lastepoch="$(cat "$stampfile" 2>/dev/null)"
  [ -z "$lastepoch" ] && lastepoch=0
  duesec=$((feedupdatehrs * 3600))

  if [ $((nowepoch - lastepoch)) -ge "$duesec" ]; then
    if feedslock; then
      updatefeeds
      echo "$nowepoch" > "$stampfile"
      feedsunlock
    else
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Feed refresh skipped - another refresh is already in progress." >> "$logfile"
    fi
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# forcefeeds is the interactive on-demand refresh reachable from the main operations screen ((F)eeds hotkey)

forcefeeds()
{
  clear
  echo -e "${CGreen}[Forcing IoC Feed Refresh]${CClear}"
  echo ""

  resolvefeedsroot

  if [ -z "$feedsroot" ]; then
    echo -e "${CRed}ERROR: No feed storage location is available right now (external drive missing). Refresh skipped.${CClear}"
  else
    mkdir -m 755 -p "$feedsroot/meta"
    if feedslock; then
      updatefeeds force
      date +%s > "$feedsroot/meta/.last_update"
      feedsunlock
      echo ""
      echo -e "${CGreen}Feed refresh complete.${CClear}"
    else
      echo -e "${CYellow}A feed refresh is already in progress - try again in a moment.${CClear}"
    fi
  fi

  echo ""
  read -rsp $'Press any key to continue...\n' -n1 key
  if [ "$timerpaused" -eq 1 ]; then renderdashboard; else timer=$timerloop; fi
}

# -------------------------------------------------------------------------------------------------------------------------
# feedsourcecounts prints a compact abbreviated breakdown, e.g. "tf=5871 sh=1756 fd=1 na=176k uh=2492 qf=231k" (10000+ as Nk).

feedsourcecounts()
{
  local f
  for f in "$feedsroot/ips.txt" "$feedsroot/domains.txt" "$feedsroot/hashes.txt"; do
    [ -s "$f" ] && cat "$f"
  done | awk -F'|' '
    {
      n = split($2, srcs, ",")
      for (i = 1; i <= n; i++) {
        s = srcs[i]
        if (s == "spamhaus-drop" || s == "spamhaus-edrop") s = "sh"; else if (s == "threatfox") s = "tf"; else if (s == "feodo") s = "fd"
        else if (s == "netapi") s = "na"; else if (s == "urlhaus") s = "uh"
        c[s]++
      }
    }
    function out(k) { if (c[k] >= 10000) printf "%s=%dk ", k, int(c[k] / 1000); else printf "%s=%d ", k, c[k] }
    END { no = split("tf sh fd na uh", ord, " "); for (i = 1; i <= no; i++) { if (ord[i] in c) out(ord[i]); shown[ord[i]] = 1 } for (k in c) if (!(k in shown)) out(k) }
  '
  local qf
  qf="$(qfeedscount)"
  if [ "$qf" -ge 10000 ]; then printf 'qf=%dk ' "$((qf / 1000))"; elif [ "$qf" -gt 0 ]; then printf 'qf=%d ' "$qf"; fi
}

feedsoldestfetch()
{
  local src oldestfile="" oldestmt="" metafile mt qfstamp=""
  [ "$enableqfeeds" = "1" ] && qfstamp="qfeeds.last"
  for src in feodo.meta spamhaus_drop.meta spamhaus_edrop.meta netapi_ips.meta netapi_domains.meta urlhaus.meta threatfox.meta $qfstamp; do
    metafile="$feedsroot/meta/$src"
    [ -f "$metafile" ] || continue
    mt="$(date -r "$metafile" +%s 2>/dev/null)"
    [ -z "$mt" ] && continue
    if [ -z "$oldestmt" ] || [ "$mt" -lt "$oldestmt" ]; then
      oldestmt="$mt"; oldestfile="$metafile"
    fi
  done
  if [ -n "$oldestfile" ]; then
    if [ "$(date -r "$oldestfile" +%Y%m%d)" = "$(date +%Y%m%d)" ]; then
      date -r "$oldestfile" +'%H:%M'
    else
      date -r "$oldestfile" +'%b %d %H:%M'
    fi
  else
    echo "n/a"
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# resolvestateroot mirrors resolvefeedsroot for the small alert-dedup/checkpoint files

resolvestateroot()
{
  checkdrivealive

  if [ -n "$extdrivelabel" ] && [ "$driveavailable" -eq 1 ]; then
    stateroot="$iocmonroot/state"
  elif [ -z "$extdrivelabel" ]; then
    stateroot="$addonsdir/state-degraded"
  else
    stateroot=""
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# _DownloadCEMLibraryFile_/_SendEMailNotification_ are TAILMON's shared AMTM email integration, adapted for IOCMON branding.

_DownloadCEMLibraryFile_()
{
   local msgStr  retCode
   case "$1" in
        update) msgStr="Updating" ;;
       install) msgStr="Installing" ;;
             *) return 1 ;;
   esac

   printf "\33[2K\r"
   printf "${CGreen}\r[INFO: ${msgStr} the shared AMTM email library script file to support email notifications...]${CClear}"
   echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: ${msgStr} the shared AMTM email library script file to support email notifications..." >> "$logfile"

   mkdir -m 755 -p "$CUSTOM_EMAIL_LIBDir"
   curl -kLSs --retry 3 --retry-delay 5 --retry-connrefused \
   "${CEM_LIB_URL}/$CUSTOM_EMAIL_LIBName" -o "$CUSTOM_EMAIL_LIBFile"
   curlCode="$?"

   if [ "$curlCode" -eq 0 ] && [ -f "$CUSTOM_EMAIL_LIBFile" ]
   then
       retCode=0
       chmod 755 "$CUSTOM_EMAIL_LIBFile"
       . "$CUSTOM_EMAIL_LIBFile"
   else
       retCode=1
       printf "\33[2K\r"
       printf "${CRed}\r[ERROR: Unable to download the shared library script file ($CUSTOM_EMAIL_LIBName).]${CClear}"
       echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - **ERROR**: Unable to download the shared AMTM email library script file [$CUSTOM_EMAIL_LIBName]." >> "$logfile"
   fi
   return "$retCode"
}

# -------------------------------------------------------------------------------------------------------------------------
# _SendEMailNotification_ - ARG1 FROM_NAME alias, ARG2 subject, ARG3 body-text file path, ARG4 body title (optional).

_SendEMailNotification_()
{
   if [ -z "${amtmIsEMailConfigFileEnabled:+xSETx}" ]
   then
       printf "\33[2K\r"
       printf "${CRed}\r[ERROR: Email library script ($CUSTOM_EMAIL_LIBFile) *NOT* FOUND.]${CClear}"
       sleep 5
       echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - **ERROR**: Email library script [$CUSTOM_EMAIL_LIBFile] *NOT* FOUND." >> "$logfile"
       emailsendrc=1
       return 1
   fi

   if [ $# -lt 3 ] || [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]
   then
       printf "\33[2K\r"
       printf "${CRed}\r[ERROR: INSUFFICIENT email parameters]${CClear}"
       sleep 5
       echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - **ERROR**: INSUFFICIENT email parameters." >> "$logfile"
       emailsendrc=1
       return 1
   fi
   local retCode  emailBodyTitleStr=""

   [ $# -gt 3 ] && [ -n "$4" ] && emailBodyTitleStr="$4"

   FROM_NAME="$1"
   _SendEMailNotification_CEM_ "$2" "-F=$3" "$emailBodyTitleStr"
   retCode="$?"

   local statustext="$2"
   [ "${#statustext}" -gt 60 ] && statustext="$(printf '%.59s' "$statustext")>"

   if [ "$retCode" -eq 0 ]
   then
     printf "\33[2K\r"
     printf "${CGreen}\r[Email notification was sent successfully (%s)]${CClear}" "$statustext"
     echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Email notification was sent successfully [$2]" >> "$logfile"
     sleep 5
   else
     printf "\33[2K\r"
     printf "${CRed}\r[ERROR: Failure to send email notification (Error Code: %s - %s).]${CClear}" "$retCode" "$statustext"
     echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - **ERROR**: Failure to send email notification [$2]" >> "$logfile"
     sleep 5
     case "$2" in
       TEST:*|"$emailfallbacksubject") ;;
       *)
         {
           emailrow "" "IOCMON raised a security alert, but the email with its details could not be delivered. Your mail provider may have rejected it for naming a flagged domain or address."
           printf "\n"
           emailrow "" "Please review the 'IOC match' lines in $logfile on the router."
         } > "$3"
         _SendEMailNotification_ "$1" "$emailfallbacksubject" "$3" "$emailfallbacksubject"
         retCode="$?" ;;
     esac
   fi

   emailsendrc="$retCode"
   return "$retCode"
}

# -------------------------------------------------------------------------------------------------------------------------
# ratelimiter caps outgoing email volume to $ratelimit/hour by tracking send timestamps in a small rolling window file

ratelimiter()
{
  [ "$ratelimit" = "0" ] && return 0

  local rlfile="$addonsdir/iocmonemails.txt" nowepoch cutoffepoch count

  nowepoch=$(date +%s)
  cutoffepoch=$((nowepoch - 3600))

  [ -f "$rlfile" ] || : > "$rlfile"
  awk -v c="$cutoffepoch" '$1>=c' "$rlfile" > "${rlfile}.tmp" && mv "${rlfile}.tmp" "$rlfile"

  count="$(wc -l < "$rlfile" | tr -d ' ')"
  [ "$count" -ge "$ratelimit" ] && return 1

  echo "$nowepoch" >> "$rlfile"
  return 0
}

# -------------------------------------------------------------------------------------------------------------------------
# loadcemlibrary is the shared AMTM CustomEMailFunctions load/install/update-check step both sendmessage

loadcemlibrary()
{
  if [ -f "$CUSTOM_EMAIL_LIBFile" ]
  then
    . "$CUSTOM_EMAIL_LIBFile"

    if [ -z "${CEM_LIB_VERSION:+xSETx}" ] || \
      _CheckLibraryUpdates_CEM_ "$CUSTOM_EMAIL_LIBDir" quiet
    then
      _DownloadCEMLibraryFile_ "update"
    fi
  else
      _DownloadCEMLibraryFile_ "install"
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# emailrow prints "label:" plus $2 HTML-escaped and word-wrapped to $emailwrapwidth (blank label = plain text, $3=b = bold)

emailrow()
{
  printf '%s\n' "$2" | awk -v l="$1" -v w="$emailwrapwidth" -v b="$3" '
    function esc(s) { gsub(/&/, "\\&amp;", s); gsub(/</, "\\&lt;", s); gsub(/>/, "\\&gt;", s); return s }
    function out(s) { print pfx (b == "b" ? "<b>" esc(s) "</b>" : esc(s)); pfx = sp }
    { v = (NR == 1 ? $0 : v " " $0) }
    END {
      ind = 0; pfx = ""
      if (l != "") { lab = l ":"; ind = (length(lab) < 13 ? 13 : length(lab) + 1); pfx = "<b>" esc(lab) "</b>" sprintf("%" (ind - length(lab)) "s", "") }
      sp = sprintf("%" ind "s", "")
      n = split(v, wd, " "); line = ""
      for (i = 1; i <= n; i++) {
        if (line == "") line = wd[i]
        else if (ind + length(line) + 1 + length(wd[i]) <= w) line = line " " wd[i]
        else { out(line); line = wd[i] }
      }
      out(line)
    }'
}

# -------------------------------------------------------------------------------------------------------------------------
# emaillinkrow prints "label:" plus a clickable link to $2, aligned with emailrow

emaillinkrow()
{
  local pad=$((12 - ${#1}))
  [ "$pad" -lt 1 ] && pad=1
  printf "<b>%s:</b>%${pad}s<a href=\"%s\">%s</a>\n" "$1" "" "$2" "$2"
}

# -------------------------------------------------------------------------------------------------------------------------
# emaildivider prints one $emailwrapwidth-wide line of "=" for the alert email layout

emaildivider()
{
  awk -v w="$emailwrapwidth" 'BEGIN { s = sprintf("%" w "s", ""); gsub(/ /, "=", s); print s }'
}

# -------------------------------------------------------------------------------------------------------------------------
# emailsection prints a bold heading ($1) between two dividers

emailsection()
{
  emaildivider
  emailrow "" "$1" b
  emaildivider
}

# -------------------------------------------------------------------------------------------------------------------------
# emailfeedname turns a comma-joined source list (e.g. urlhaus,threatfox) into display names (URLhaus and ThreatFox)

emailfeedname()
{
  echo "$1" | awk -F',' '{
    for (i = 1; i <= NF; i++) {
      s = $i
      if (s == "feodo") s = "Feodo Tracker"; else if (s == "spamhaus-drop") s = "Spamhaus DROP"; else if (s == "spamhaus-edrop") s = "Spamhaus EDROP"
      else if (s == "urlhaus") s = "URLhaus"; else if (s == "threatfox") s = "ThreatFox"; else if (s == "qfeeds") s = "Q-Feeds"; else if (s == "netapi") s = "NetAPI.com"
      o = (i == 1 ? s : (i == NF ? o " and " s : o ", " s))
    }
    print o
  }'
}

# -------------------------------------------------------------------------------------------------------------------------
# emailfamilyrows splits a comma-joined feed family string into family/threat/confidence/tags email rows

emailfamilyrows()
{
  local tab label value
  tab="$(printf '\t')"
  echo "$1" | awk -F',' '
    function trim(s) { sub(/^ +/, "", s); sub(/ +$/, "", s); return s }
    {
      for (i = 1; i <= NF; i++) {
        p = trim($i); if (p == "") continue
        if (p ~ /; [0-9]+ URL\(s\)/) {
          t = ""; k = index(p, "; tags: ")
          if (k) { t = substr(p, k + 8); p = substr(p, 1, k - 1) }
          print "family\t" p; if (t != "") print "tags\t" t
        } else if (match(p, / \([^()]*confidence: [0-9]+[^()]*\)$/)) {
          name = substr(p, 1, RSTART - 1); inner = substr(p, RSTART + 2, RLENGTH - 3)
          print "family\t" (name == "" ? "unknown" : name)
          n = split(inner, f, "; ")
          for (j = 1; j <= n; j++) {
            if (f[j] ~ /^confidence: /) print "confidence\t" substr(f[j], 13) "%"
            else if (f[j] ~ /^tags: /) print "tags\t" substr(f[j], 7)
            else if (f[j] != "") print "threat\t" f[j]
          }
        } else print "family\t" p
      }
    }' | while IFS="$tab" read -r label value; do emailrow "$label" "$value"; done
}

# -------------------------------------------------------------------------------------------------------------------------
# emailalertbody prints one alert as an intro line, a section heading and labelled rows, shared by single and batch emails

emailalertbody()
{
  local kind="$1" indicator="$2" source="$3" detail="$4" feeds plural="" hash fam
  feeds="$(emailfeedname "$source")"
  case "$source" in *,*) plural="s" ;; esac
  case "$kind" in
    conntrack)
      emailrow "" "IOCMON detected an active connection ($indicator, local device -> remote host)"
      emailsection "Matches the $feeds IoC feed$plural"
      emailfamilyrows "$detail"
      emailrow "advice" "This address may be a botnet command-and-control server or other malicious host. Please review connected devices and investigate for compromise." ;;
    dns)
      emailrow "" "IOCMON observed a DNS query ($indicator, local device -> queried domain)"
      if [ "$source" = "dns-tunnel-heuristic" ]; then
        emailsection "Matches a DNS-tunneling/exfiltration heuristic"
        emailrow "reason" "$detail"
        emailrow "note" "A pattern-based suspicion, not a confirmed threat-intelligence match: this domain is not in any known-malicious feed. A legitimate service with an unusually long or fast-changing hostname can trigger this."
        emailrow "advice" "Please verify manually before treating this as a confirmed compromise. If it is expected, add the domain to the DNS exceptions list (Advanced Settings - DNS Watch & Tunneling Detection) to stop it recurring."
      else
        emailsection "Matches the $feeds IoC feed$plural"
        emailfamilyrows "$detail"
        emailrow "advice" "A device on your network may be compromised or contacting a malware-distribution site."
      fi ;;
    auth)
      emailrow "" "IOCMON detected repeated failed login attempts"
      emailsection "Possible brute-force login attempts"
      emailrow "service" "$source"
      emailrow "from" "$indicator"
      emailrow "attempts" "$detail"
      emailrow "advice" "Please verify this is not an authorized user and consider blocking this address." ;;
    fsintegrity)
      emailrow "" "IOCMON flagged a filesystem-integrity event"
      if isfeedmatchsource "$source"; then
        hash="${detail#hash match }"; hash="${hash%% *}"
        fam="${detail#hash match * (}"; fam="${fam%)}"
        emailsection "Matches the $feeds IoC feed$plural"
        emailrow "file" "$indicator"
        emailrow "hash" "$hash"
        emailfamilyrows "$fam"
      else
        emailsection "Filesystem-integrity change"
        emailrow "file" "$indicator"
        emailrow "reason" "$source"
        emailrow "detail" "$detail"
      fi
      emailrow "advice" "Please review this file/change as soon as possible." ;;
    cron)
      emailrow "" "IOCMON detected a new scheduled task that it did not create"
      emailsection "Unexpected new cron entry"
      emailrow "entry" "$indicator"
      if [ "$source" = "cru" ]; then emailrow "advice" "This can indicate cron-based persistence from malware. Please review with 'cru l'."
      else emailrow "advice" "This can indicate cron-based persistence from malware. Please review the Entware crontab."; fi ;;
    simulated)
      emailrow "" "This is a SIMULATED detection triggered via the (T)est hotkey to confirm IOCMON's full detection-to-alert pipeline is working."
      emailsection "SIMULATED TEST - no real compromise has been detected"
      emailrow "indicator" "$indicator"
      emailrow "feed" "$feeds"
      emailfamilyrows "${detail% - SIMULATED TEST*}" ;;
    *)
      emailrow "" "IOCMON detected a security event ($kind)"
      emailsection "$source"
      emailrow "indicator" "$indicator"
      emailrow "detail" "$detail" ;;
  esac
  abusechemaillinks "$kind" "$indicator" "$source" "$detail"
  emaildivider
}

# -------------------------------------------------------------------------------------------------------------------------
# sendmessage is the single shared entry point every IOCMON alert type routes through

sendmessage()
{
  local success="$1" kind="$2" indicator="$3" source="$4" detail="$5" repip="$6" inteltarget="$7"

  [ "$enablealertemail" = "1" ] || return

  loadcemlibrary

  cemIsFormatHTML=true
  cemIsVerboseMode=false
  tmpEMailBodyFile="/tmp/var/tmp/tmpEMailBody_${scriptFileNTag}.$$.TXT"

  ratelimiter
  emaillimit="$?"
  if [ "$emaillimit" -eq 0 ]
    then

    local emailSubject="" emailBodyTitle=""

    case "$kind" in
      test) emailSubject="TEST: IOCMON email notification test" ;;
      simulated) emailSubject="TEST: Simulated IOC detection ($indicator)" ;;
      conntrack) emailSubject="ALERT: Connection to known-malicious IP ($indicator)" ;;
      dns)
        if [ "$source" = "dns-tunnel-heuristic" ]; then emailSubject="ALERT: Suspicious DNS query pattern detected ($indicator)"
        else emailSubject="ALERT: DNS query for known-malicious domain ($indicator)"; fi ;;
      auth) emailSubject="WARNING: Possible brute-force login attempts from $indicator" ;;
      fsintegrity) emailSubject="ALERT: Filesystem-integrity event - $indicator" ;;
      cron) emailSubject="ALERT: Unexpected new cron entry detected" ;;
      *) emailSubject="ALERT: IOCMON detected a security event ($kind)" ;;
    esac
    emailBodyTitle="$emailSubject"

    {
      printf "<b>Date/Time:</b> %s\n\n" "$(date +'%b %d %Y %X')"
      if [ "$kind" = "test" ]; then
        emailrow "" "This is a test email requested via 'iocmon.sh -email' to confirm AMTM email notifications are configured correctly. If you received this, IOCMON's email pipeline is working."
      else
        emailalertbody "$kind" "$indicator" "$source" "$detail"
      fi
      [ -n "$repip" ] && reputationemailblock "$repip" "$kind"
      [ -n "$inteltarget" ] && astraeaemailblock "$inteltarget"
    } > "$tmpEMailBodyFile"

    _SendEMailNotification_ "IOCMON v$version" "$emailSubject" "$tmpEMailBodyFile" "$emailBodyTitle"

  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# sendbatchmessage sends ONE email listing every alert queued this cycle

sendbatchmessage()
{
  local batchfile="$1" count="$2" tab

  [ "$enablealertemail" = "1" ] || return

  loadcemlibrary

  cemIsFormatHTML=true
  cemIsVerboseMode=false
  tmpEMailBodyFile="/tmp/var/tmp/tmpEMailBody_${scriptFileNTag}.$$.TXT"
  tab="$(printf '\t')"

  ratelimiter
  emaillimit="$?"
  if [ "$emaillimit" -eq 0 ]
    then

    local emailSubject="ALERT: IOCMON detected $count security events in one scan cycle" emailBodyTitle
    emailBodyTitle="$emailSubject"

    {
      printf "<b>Date/Time:</b> %s\n\n" "$(date +'%b %d %Y %X')"
      emailrow "" "IOCMON detected $count separate security events during a single scan cycle. Rather than send $count separate emails, they are grouped below."
      local i=0 bkind bindicator bsource bdetail brepip bintel
      while IFS="$tab" read -r bkind bindicator bsource bdetail brepip bintel; do
        [ "$brepip" = "-" ] && brepip=""
        [ "$bintel" = "-" ] && bintel=""
        i=$((i+1))
        printf "\n<b>Event %d of %d (%s)</b>\n" "$i" "$count" "$bkind"
        emailalertbody "$bkind" "$bindicator" "$bsource" "$bdetail"
        [ -n "$brepip" ] && reputationemailblock "$brepip" "$bkind"
        [ -n "$bintel" ] && astraeaemailblock "$bintel"
      done < "$batchfile"
      printf "\n"
      emailrow "" "Please review each item above."
    } > "$tmpEMailBodyFile"

    _SendEMailNotification_ "IOCMON v$version" "$emailSubject" "$tmpEMailBodyFile" "$emailBodyTitle"

  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# queueemailalert/flushemailbatch become one grouped email instead of one email per alert

queueemailalert()
{
  local kind="$1" indicator="$2" source="$3" detail="$4" repip="$5" inteltarget="$6"

  resolvestateroot
  if [ -z "$stateroot" ]; then
    sendmessage 1 "$kind" "$indicator" "$source" "$detail" "" "$inteltarget"
    return
  fi

  mkdir -m 755 -p "$stateroot"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$kind" "$indicator" "$source" "$detail" "${repip:--}" "${inteltarget:--}" >> "$stateroot/email_batch.pending"
}

flushemailbatch()
{
  resolvestateroot
  [ -n "$stateroot" ] || return

  local batchfile="$stateroot/email_batch.pending" sendfile="$stateroot/email_batch.sending" count tab
  local retryfile="$stateroot/email_batch.retry" tries=0 nextretry=0

  [ -s "$batchfile" ] || return
  tab="$(printf '\t')"
  [ -f "$retryfile" ] && read -r tries nextretry < "$retryfile"
  case "$tries" in ""|*[!0-9]*) tries=0 ;; esac
  case "$nextretry" in ""|*[!0-9]*) nextretry=0 ;; esac
  [ "$(date +%s)" -lt "$nextretry" ] && ! grep -q "^simulated$tab" "$batchfile" && return
  emailsendrc=0
  mv "$batchfile" "$sendfile"

  count="$(wc -l < "$sendfile" | tr -d ' ')"

  if [ "$count" -le 1 ]; then
    local kind indicator source detail repip inteltarget
    IFS="$tab" read -r kind indicator source detail repip inteltarget < "$sendfile"
    [ "$repip" = "-" ] && repip=""
    [ "$inteltarget" = "-" ] && inteltarget=""
    sendmessage 1 "$kind" "$indicator" "$source" "$detail" "$repip" "$inteltarget"
  else
    sendbatchmessage "$sendfile" "$count"
  fi

  if [ "$emailsendrc" -eq 0 ] || ! grep -qv "^simulated$tab" "$sendfile"; then
    rm -f "$sendfile"
    [ "$emailsendrc" -eq 0 ] && rm -f "$retryfile"
  elif [ "$((tries + 1))" -ge 6 ]; then
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - **ERROR**: Gave up emailing $count alert(s) after $((tries + 1)) attempts; see the IOC match lines in this log." >> "$logfile"
    rm -f "$sendfile" "$retryfile"
  else
    echo "$((tries + 1)) $(($(date +%s) + 600))" > "$retryfile"
    { cat "$sendfile"; cat "$batchfile" 2>/dev/null; } | tail -n 100 > "$batchfile.tmp" && mv -f "$batchfile.tmp" "$batchfile"
    rm -f "$sendfile"
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# ispublicip succeeds only for a globally routable IPv4/IPv6 address worth an AbuseIPDB lookup

ispublicip()
{
  local a b
  case "$1" in
    *:*) case "$1" in [23]*) return 0 ;; *) return 1 ;; esac ;;
  esac
  echo "$1" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' || return 1
  a="${1%%.*}"; b="${1#*.}"; b="${b%%.*}"
  case "$a" in 0|10|127) return 1 ;; esac
  [ "$a" -ge 224 ] && return 1
  [ "$a" -eq 169 ] && [ "$b" -eq 254 ] && return 1
  [ "$a" -eq 172 ] && [ "$b" -ge 16 ] && [ "$b" -le 31 ] && return 1
  [ "$a" -eq 192 ] && [ "$b" -eq 168 ] && return 1
  [ "$a" -eq 100 ] && [ "$b" -ge 64 ] && [ "$b" -le 127 ] && return 1
  return 0
}

# -------------------------------------------------------------------------------------------------------------------------
# shortusagetype abbreviates an AbuseIPDB usageType for the compact dashboard/IoC-log tag

shortusagetype()
{
  case "$1" in
    "Data Center/Web Hosting/Transit") echo "DC/Hosting" ;;
    "Fixed Line ISP") echo "ISP" ;;
    "Mobile ISP") echo "MobileISP" ;;
    "Content Delivery Network") echo "CDN" ;;
    "Organization") echo "Org" ;;
    "Government") echo "Gov" ;;
    "University/College/School") echo "Edu" ;;
    "Search Engine Spider") echo "Spider" ;;
    "") echo "n/a" ;;
    *) echo "$1" ;;
  esac
}

# -------------------------------------------------------------------------------------------------------------------------
# dnsreplyip finds the last public IP dnsmasq's own reply/cached log lines gave for $1 (or a subdomain of it) - never resolves anything itself

dnsreplyip()
{
  local dom="$1" logf="${dnslogresolved:-/tmp/syslog.log}"
  if dnsusesagh; then aghreplyip "$dom"; return; fi
  [ -n "$dom" ] && [ -f "$logf" ] || return
  tail -n 20000 "$logf" | grep -F 'dnsmasq' | grep -E ' (reply|cached) ' | awk -v d="$dom" '
    function usable(v) {
      if (v ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return (v !~ /^(0|10|127)\./ && v !~ /^192\.168\./)
      return (v ~ /^[23][0-9a-fA-F]*:[0-9a-fA-F:]+$/)
    }
    {
      name = ""; val = ""
      for (i = 1; i <= NF - 3; i++) if (($i == "reply" || $i == "cached") && $(i+2) == "is") { name = $(i+1); val = $(i+3); break }
      if (name == "") { chase = 0; next }
      hit = (name == d || substr(name, length(name) - length(d)) == "." d)
      if (hit && usable(val)) { ip = val; chase = 0; next }
      if (hit && val == "<CNAME>") { chase = 1; next }
      if (chase && usable(val)) { ip = val; chase = 0; next }
      if (val != "<CNAME>") chase = 0
    }
    END { if (ip != "") print ip }
  '
}

# -------------------------------------------------------------------------------------------------------------------------
# abuseipdbusedtoday echoes how many AbuseIPDB lookups IOCMON has made today

abuseipdbusedtoday()
{
  [ -n "$stateroot" ] && [ -f "$stateroot/abuseipdb_usage" ] || { echo 0; return; }
  awk -F'\t' -v t="$(date +%Y%m%d)" '$1==t{c=$2} END{print c+0}' "$stateroot/abuseipdb_usage"
}

# -------------------------------------------------------------------------------------------------------------------------
# abuseipdbblocked succeeds while a 429/bad-key back-off is in force, echoing its reason

abuseipdbblocked()
{
  local until reason
  [ -n "$stateroot" ] && [ -f "$stateroot/abuseipdb_block" ] || return 1
  IFS="$(printf '\t')" read -r until reason < "$stateroot/abuseipdb_block"
  validateint "$until" 0 || return 1
  [ "$(date +%s)" -lt "$until" ] || { rm -f "$stateroot/abuseipdb_block"; return 1; }
  echo "$reason"
  return 0
}

# -------------------------------------------------------------------------------------------------------------------------
# abuseipdbcached echoes $1's cache record if it is younger than abuseipdbcachehrs

abuseipdbcached()
{
  [ -f "$stateroot/abuseipdb_cache.db" ] || return
  awk -F'|' -v ip="$1" -v cut="$(( $(date +%s) - abuseipdbcachehrs * 3600 ))" '$1==ip && $2+0>=cut' "$stateroot/abuseipdb_cache.db" | tail -n1
}

# -------------------------------------------------------------------------------------------------------------------------
# abuseipdbquery calls /api/v2/check (verbose) for $1 and caches the parsed result; sets $repfailreason on failure

abuseipdbquery()
{
  local ip="$1" body="/tmp/iocmon_aipdb_body.$$" hdrs="/tmp/iocmon_aipdb_hdr.$$" mode code rc nowepoch today used
  local remaining limit reset retry rec cats cache="$stateroot/abuseipdb_cache.db" usagefile="$stateroot/abuseipdb_usage"
  repfailreason=""
  for mode in verbose plain; do
    rm -f "$body" "$hdrs"
    set -- -G --data-urlencode "ipAddress=$ip" --data "maxAgeInDays=$abuseipdbmaxage"
    [ "$mode" = "verbose" ] && set -- "$@" --data "verbose"
    code="$(printf 'header = "Key: %s"\n' "$abuseipdbapikey" | curl --silent --connect-timeout 10 --max-time 180 --max-filesize 2097152 -K - -H "Accept: application/json" -D "$hdrs" -o "$body" -w '%{http_code}' "$@" "https://api.abuseipdb.com/api/v2/check")"
    rc=$?
    [ "$rc" -eq 63 ] && [ "$mode" = "verbose" ] || break
  done

  nowepoch=$(date +%s); today=$(date +%Y%m%d)
  remaining="$(grep -i '^x-ratelimit-remaining:' "$hdrs" 2>/dev/null | tail -n1 | tr -d '\r' | awk '{print $2}')"
  limit="$(grep -i '^x-ratelimit-limit:' "$hdrs" 2>/dev/null | tail -n1 | tr -d '\r' | awk '{print $2}')"
  reset="$(grep -i '^x-ratelimit-reset:' "$hdrs" 2>/dev/null | tail -n1 | tr -d '\r' | awk '{print $2}')"
  retry="$(grep -i '^retry-after:' "$hdrs" 2>/dev/null | tail -n1 | tr -d '\r' | awk '{print $2}')"

  if [ -n "$code" ] && [ "$code" != "000" ]; then
    used="$(abuseipdbusedtoday)"
    if [ -f "$usagefile" ]; then
      [ -n "$remaining" ] || remaining="$(cut -f3 "$usagefile" | tail -n1)"
      [ -n "$limit" ] || limit="$(cut -f4 "$usagefile" | tail -n1)"
      [ -n "$reset" ] || reset="$(cut -f5 "$usagefile" | tail -n1)"
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$today" "$((used + 1))" "$remaining" "$limit" "$reset" > "$usagefile"
  fi

  case "$code" in
    200) ;;
    429)
      validateint "$retry" 1 || retry=3600
      validateint "$reset" 1 && [ "$reset" -gt "$nowepoch" ] && retry=$((reset - nowepoch))
      printf '%s\t%s\n' "$((nowepoch + retry))" "AbuseIPDB rate limit reached (HTTP 429)" > "$stateroot/abuseipdb_block"
      repfailreason="AbuseIPDB rate limit reached (HTTP 429) - lookups paused for ${retry}s"
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: $repfailreason." >> "$logfile"
      rm -f "$body" "$hdrs"; return 1 ;;
    401|403)
      printf '%s\t%s\n' "$((nowepoch + 3600))" "API key rejected (HTTP $code)" > "$stateroot/abuseipdb_block"
      repfailreason="AbuseIPDB rejected the API key (HTTP $code) - lookups paused for 1h, check item 13 under Feed Sources, Reputation, API Keys and Lookups"
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: $repfailreason." >> "$logfile"
      rm -f "$body" "$hdrs"; return 1 ;;
    *)
      repfailreason="AbuseIPDB lookup failed (curl exit $rc, HTTP ${code:-000})"
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: $repfailreason for $ip." >> "$logfile"
      rm -f "$body" "$hdrs"; return 1 ;;
  esac

  cats="$(grep -o '"categories":\[[0-9,]*\]' "$body" 2>/dev/null | sed 's/.*\[//; s/\]//' | tr ',' '\n' | grep -E '^[0-9]+$' | sort | uniq -c | sort -rn | head -n 3 | awk '
    BEGIN { split("DNS Compromise,DNS Poisoning,Fraud Orders,DDoS Attack,FTP Brute-Force,Ping of Death,Phishing,Fraud VoIP,Open Proxy,Web Spam,Email Spam,Blog Spam,VPN IP,Port Scan,Hacking,SQL Injection,Spoofing,Brute-Force,Bad Web Bot,Exploited Host,Web App Attack,SSH,IoT Targeted", cn, ",") }
    { nm = ($2 + 0 >= 1 && $2 + 0 <= 23) ? cn[$2 + 0] : "Category " $2; printf "%s%s(%s)", (NR > 1 ? "," : ""), nm, $1 }
  ')"

  rec="$(sed 's/"reports":.*//' "$body" | awk -v ip="$ip" -v now="$nowepoch" -v cats="$cats" '
    function jv(s, k,   p, r, c, out) {
      p = index(s, "\"" k "\":"); if (p == 0) return ""
      r = substr(s, p + length(k) + 3); sub(/^ +/, "", r)
      if (substr(r, 1, 1) == "\"") {
        r = substr(r, 2); out = ""
        while (length(r) > 0) {
          c = substr(r, 1, 1)
          if (c == "\\") { out = out substr(r, 2, 1); r = substr(r, 3); continue }
          if (c == "\"") break
          out = out c; r = substr(r, 2)
        }
        return out
      }
      if (match(r, /^[^],}]*/)) { out = substr(r, 1, RLENGTH); return (out == "null" ? "" : out) }
      return ""
    }
    function cl(v) { gsub(/[\t|]/, " ", v); return v }
    { s = s $0 }
    END {
      if (index(s, "\"abuseConfidenceScore\":") == 0) exit 1
      hn = ""; q = index(s, "\"hostnames\":[")
      if (q > 0) { hn = substr(s, q + 13); hn = substr(hn, 1, index(hn, "]") - 1); gsub(/"/, "", hn) }
      last = jv(s, "lastReportedAt"); sub(/T.*/, "", last)
      printf "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n", ip, now, jv(s, "abuseConfidenceScore") + 0, jv(s, "totalReports") + 0, jv(s, "numDistinctUsers") + 0, last, cl(jv(s, "countryCode")), cl(jv(s, "countryName")), cl(jv(s, "usageType")), cl(jv(s, "isp")), cl(jv(s, "domain")), jv(s, "isTor"), jv(s, "isWhitelisted"), cl(hn), cats
    }
  ')"
  rm -f "$body" "$hdrs"

  if [ -z "$rec" ]; then
    repfailreason="AbuseIPDB returned an unreadable reply (HTTP 200)"
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: $repfailreason for $ip." >> "$logfile"
    return 1
  fi

  { [ -f "$cache" ] && awk -F'|' -v ip="$ip" -v cut="$((nowepoch - abuseipdbcachehrs * 3600))" '$1!=ip && $2+0>=cut' "$cache"; printf '%s\n' "$rec"; } > "${cache}.tmp"
  mv "${cache}.tmp" "$cache"
  return 0
}

# -------------------------------------------------------------------------------------------------------------------------
# reputationlookup enriches one conntrack/dns/auth alert via AbuseIPDB, setting $reptag (compact) and $repip (cache key)

reputationlookup()
{
  local kind="$1" indicator="$2" source="$3" ip="" target="" rec="" reason="" cachednote="" cyclefile="${abuseipdbcyclefile:-/tmp/iocmon_aipdb_cycle.$$}" cyclecount=0 now
  local rip epoch score total users last cc cname usage isp domain tor wl hostnames cats flags="" catnames testmark="" testtag="" manualnote=""
  reptag=""; repip=""; repreason=""; repscore=""
  [ "$enableabuseipdb" = "1" ] && [ -n "$abuseipdbapikey" ] && [ -n "$stateroot" ] || return
  [ "$kind" = "simulated" ] && { testmark=" [SIMULATED TEST]"; testtag="TEST "; }
  [ "$kind" = "lookup" ] && { testmark=" [MANUAL LOOKUP]"; manualnote="MANUAL LOOKUP - "; }

  case "$kind" in
    conntrack|auth)
      target="${indicator#*->}"; ip="$target"
      ispublicip "$ip" || return ;;
    dns)
      target="${indicator#*->}"
      ip="$(dnsreplyip "$target")"
      if [ -z "$ip" ]; then
        reason="no public IP for this domain in dnsmasq's reply log"
      elif ! ispublicip "$ip"; then
        reason="dnsmasq answered with non-public $ip"; ip=""
      fi ;;
    simulated)
      target="${indicator%%/*}"
      if ispublicip "$target"; then
        ip="$target"
      elif echo "$target" | grep -qE '^[0-9a-fA-F]{32,}$'; then
        reason="the test indicator is a file hash - AbuseIPDB only checks IP addresses"
      elif echo "$target" | grep -q '[A-Za-z].*\.'; then
        ip="$(dnsreplyip "$target")"
        [ -n "$ip" ] && ispublicip "$ip" || { reason="no public IP for this test domain in dnsmasq's reply log"; ip=""; }
      else
        reason="the test indicator $target is not a public IP address"
      fi ;;
    lookup)
      target="$indicator"; ip="$target"
      ispublicip "$ip" || { reason="$ip is not a public IP address"; ip=""; } ;;
    *) return ;;
  esac

  if [ -n "$ip" ]; then
    [ -z "$testtag" ] && rec="$(abuseipdbcached "$ip")"
    if [ -n "$rec" ]; then
      cachednote=" (cached)"
    elif reason="$(abuseipdbblocked)"; then
      reason="paused: $reason"
    elif [ "$(abuseipdbusedtoday)" -ge "$abuseipdbdailymax" ]; then
      reason="daily lookup ceiling ($abuseipdbdailymax) reached"
    else
      reason=""
      [ -f "$cyclefile" ] && cyclecount="$(cat "$cyclefile" 2>/dev/null)"
      validateint "$cyclecount" 0 || cyclecount=0
      if [ -z "$testmark" ] && [ "$cyclecount" -ge "$abuseipdbcyclemax" ]; then
        reason="per-cycle lookup limit ($abuseipdbcyclemax) reached"
      else
        echo "$((cyclecount + 1))" > "$cyclefile"
        inlinestatus "AbuseIPDB reputation lookup for $ip"
        if abuseipdbquery "$ip"; then rec="$(abuseipdbcached "$ip")"; else reason="$repfailreason"; fi
      fi
    fi
  fi

  now="$(date +'%b %d %Y %X')"
  mkdir -m 755 -p "$stateroot"
  if [ -z "$rec" ]; then
    [ -n "$reason" ] || return
    repreason="$reason"
    echo "$now | ${ip:-$target} | not checked: $reason | $kind/$source $indicator$testmark" >> "$stateroot/reputation.log"
    rotatelogfile "$stateroot/reputation.log" "$logsize"
    return
  fi

  IFS='|' read -r rip epoch score total users last cc cname usage isp domain tor wl hostnames cats <<EOF
$rec
EOF
  [ "$tor" = "true" ] && flags="Tor exit"
  [ "$wl" = "true" ] && flags="${flags:+$flags, }AbuseIPDB-whitelisted"
  catnames="$(echo "$cats" | sed 's/([0-9]*)//g')"

  repip="$ip"
  repscore="$score"
  reptag="${testtag}AbuseIPDB $ip ${score}% ${total}r/${users}u ${cc:-??} $(shortusagetype "$usage")"
  [ "$tor" = "true" ] && reptag="$reptag Tor"
  [ "$wl" = "true" ] && reptag="$reptag Whitelisted"
  [ -n "$catnames" ] && reptag="$reptag $catnames"

  echo "$now | $ip | ${score}% | ${total} reports/${users} users | last ${last:-never} | ${cc:-??} | $(shortusagetype "$usage") | ${isp:-n/a} | ${flags:-no flags} | ${cats:-no categories} | $kind/$source $indicator${cachednote}${testmark}" >> "$stateroot/reputation.log"
  rotatelogfile "$stateroot/reputation.log" "$logsize"
  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: ${testtag:+SIMULATED TEST - }${manualnote}AbuseIPDB reputation for $ip ($kind $indicator): ${score}% abuse confidence, ${total} report(s) from ${users} user(s) in the last ${abuseipdbmaxage} days, last reported ${last:-never}, ${cname:-${cc:-unknown country}}, ${usage:-unknown usage}, ISP ${isp:-n/a}${flags:+, $flags}${cats:+, categories: $cats}${cachednote}." >> "$logfile"
}

# -------------------------------------------------------------------------------------------------------------------------
# reputationemailblock prints the full AbuseIPDB detail for $1 (from the cache) as email body lines; $2=simulated marks a test

reputationemailblock()
{
  local ip="$1" rec rip epoch score total users last cc cname usage isp domain tor wl hostnames cats note="informational only"
  [ -n "$ip" ] && [ -n "$stateroot" ] && [ -f "$stateroot/abuseipdb_cache.db" ] || return
  [ "$2" = "simulated" ] && note="SIMULATED TEST (live data, real feed IP)"
  rec="$(awk -F'|' -v ip="$ip" '$1==ip' "$stateroot/abuseipdb_cache.db" | tail -n1)"
  [ -n "$rec" ] || return
  IFS='|' read -r rip epoch score total users last cc cname usage isp domain tor wl hostnames cats <<EOF
$rec
EOF
  printf "\n"
  emailsection "AbuseIPDB reputation for $ip"
  emailrow "note" "$note"
  emailrow "score" "${score}% abuse confidence"
  emailrow "reports" "$total from $users distinct user(s) in the last $abuseipdbmaxage days"
  emailrow "last report" "${last:-never}"
  emailrow "categories" "${cats:-none}"
  emailrow "country" "${cname:-${cc:-unknown}}${cname:+ (${cc})}"
  emailrow "usage type" "${usage:-n/a}"
  emailrow "ISP" "${isp:-n/a}"
  emailrow "domain" "${domain:-n/a}"
  emailrow "hostnames" "${hostnames:-none}"
  emailrow "Tor exit" "${tor:-n/a}"
  emailrow "whitelisted" "${wl:-n/a}"
  emaillinkrow "details" "https://www.abuseipdb.com/check/$ip"
  emaildivider
}

# -------------------------------------------------------------------------------------------------------------------------
# astraeatarget $1=kind $2=indicator prints the name or address Astraea can be asked about, or nothing

astraeatarget()
{
  local t
  case "$1" in
    dns|conntrack) t="${2#*->}" ;;
    simulated) t="${2%%/*}" ;;
    *) return 0 ;;
  esac
  case "$t" in *.*|*:*) echo "$t" ;; esac
}

# -------------------------------------------------------------------------------------------------------------------------
# astraeaintel $1=name or address asks Astraea for its verdict (information only), setting inteltag/inteltarget and caching the reason

astraeaintel()
{
  local target="$1" out v reason short
  inteltag=""; inteltarget=""
  [ -n "$target" ] && [ -x "$astraeascript" ] || return 0
  if which timeout >/dev/null 2>&1; then
    out="$(timeout 10 "$astraeascript" intel "$target" 2>/dev/null)"
  else
    out="$("$astraeascript" intel "$target" 2>/dev/null)"
  fi
  out="$(echo "$out" | grep '^verdict|' | tail -n 1)"
  v="$(echo "$out" | cut -d'|' -f2)"
  case "$v" in clear|confirm|unknown|contained) ;; *) return 0 ;; esac
  reason="$(echo "$out" | cut -d'|' -f3- | tr '|\t' '//')"
  short="$reason"
  [ "${#short}" -gt 100 ] && short="$(printf '%.97s' "$reason")..."
  inteltarget="$target"
  inteltag="Astraea $v: ${short:-no detail}"
  { awk -F'\t' -v t="$target" '$1 != t' "$astraeaintelfile" 2>/dev/null | tail -n 200; printf '%s\t%s\t%s\n' "$target" "$v" "$reason"; } > "$astraeaintelfile.t"
  mv -f "$astraeaintelfile.t" "$astraeaintelfile"
  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Astraea's verdict on $target (information only): $v - ${reason:-no detail}" >> "$logfile"
}

# -------------------------------------------------------------------------------------------------------------------------
# astraeaemailblock $1=name or address prints Astraea's cached verdict on it as email body lines

astraeaemailblock()
{
  local rec v reason
  [ -n "$1" ] && [ -f "$astraeaintelfile" ] || return 0
  rec="$(awk -F'\t' -v t="$1" '$1 == t' "$astraeaintelfile" | tail -n 1)"
  [ -n "$rec" ] || return 0
  v="$(echo "$rec" | cut -f2)"; reason="$(echo "$rec" | cut -f3)"
  printf "\n"
  emailsection "Astraea certificate intel for $1"
  emailrow "note" "information only - Astraea's view of this site's certificates; it does not change this alert"
  emailrow "verdict" "$v"
  emailrow "reason" "${reason:-no detail}"
  emaildivider
}

# -------------------------------------------------------------------------------------------------------------------------
# reputationstatus echoes the dashboard's compact AbuseIPDB slot, fitted to $1 visible characters

reputationstatus()
{
  local budget="${1:-40}" line ip score cc used plain scorecolor
  if [ "$enableabuseipdb" != "1" ] || [ -z "$abuseipdbapikey" ]; then
    echo -e "${CDkGray}AbuseIPDB off${CClear}"; return
  fi
  if abuseipdbblocked >/dev/null; then
    echo -e "${CYellow}AbuseIPDB paused (rate limit/key)${CClear}"; return
  fi
  used="$(abuseipdbusedtoday)"
  line=""
  [ -n "$stateroot" ] && line="$(logall "$stateroot/reputation.log" | grep -E '^[^|]*\| [^|]* \| [0-9]+% \|' | grep -vF '[MANUAL LOOKUP]' | tail -n1)"
  if [ -z "$line" ]; then
    echo -e "${CWhite}AbuseIPDB: no lookups yet (${CGreen}${used}/${abuseipdbdailymax}${CWhite})${CClear}"; return
  fi
  ip="$(echo "$line" | cut -d'|' -f2 | tr -d ' ')"
  score="$(echo "$line" | cut -d'|' -f3 | tr -dc '0-9')"
  cc="$(echo "$line" | cut -d'|' -f6 | tr -d ' ')"
  local testpfx=""
  case "$line" in *"[SIMULATED TEST]"*) testpfx="TEST " ;; esac
  plain="${testpfx}AbuseIPDB ${score}% ${ip} ${cc} (${used}/${abuseipdbdailymax})"
  if [ "${#plain}" -gt "$budget" ] && [ -n "$cc" ]; then
    cc=""; plain="${testpfx}AbuseIPDB ${score}% ${ip} (${used}/${abuseipdbdailymax})"
  fi
  if [ "${#plain}" -gt "$budget" ]; then
    if [ $(( ${#ip} - (${#plain} - budget) - 1 )) -ge 7 ]; then ip="$(printf "%.$(( ${#ip} - (${#plain} - budget) - 1 ))s" "$ip")>"; else ip="-"; fi
  fi
  scorecolor="$CGreen"
  [ "$score" -ge 25 ] && scorecolor="$CYellow"
  [ "$score" -ge 75 ] && scorecolor="$CRed"
  echo -e "${CYellow}${testpfx}${CWhite}AbuseIPDB ${scorecolor}${score}%${CClear} ${CGreen}${ip}${CClear} ${cc:+$cc }(${CGreen}${used}/${abuseipdbdailymax}${CClear})"
}

# -------------------------------------------------------------------------------------------------------------------------
# isfeedmatchsource tells a real feed-indicator match ($1=source) apart from a behavioral/heuristic detection.

isfeedmatchsource()
{
  case "$1" in
    dns-tunnel-heuristic|dropbear|httpd|nvram-change|ssh-directory-change|startup-script-edit|router-config-override|new-executable|startup-script-deleted|router-config-deleted|permission-escalation|cru|entware-cron|nat-rule|etc-critical-new|etc-critical-modified|etc-critical-deleted) return 1 ;;
    *) return 0 ;;
  esac
}

# -------------------------------------------------------------------------------------------------------------------------
# alertseverity sets $alertsev to critical/warning/info for kind $1, indicator $2, source $3, detail $4, AbuseIPDB score $5

alertseverity()
{
  local kind="$1" indicator="$2" source="$3" detail="$4" score="$5"
  alertsev="critical"
  case "$kind" in
    dns)
      if [ "$source" = "dns-tunnel-heuristic" ] || indomainlist "${indicator#*->}" "$dnssharedhosts"; then
        alertsev="info"
      else
        case "$detail" in *botnet_cc*) return ;; esac
        case "$score" in ''|*[!0-9]*) ;; *) [ "$score" -ge "$dnsescalatescore" ] && return ;; esac
        alertsev="warning"
      fi ;;
    nvram)
      case " $nvramruntimevars " in *" $indicator "*) alertsev="warning" ;; esac ;;
  esac
}

# -------------------------------------------------------------------------------------------------------------------------
# raisealert is the single entry point every detection check routes an IOC/brute-force match through.

raisealert()
{
  local kind="$1" indicator="$2" source="$3" detail="$4" dedupkey="${5:-$2}"
  local key="${kind}|${dedupkey}" nowepoch cooldownsec=21600 lastepoch=0 sevtag
  reptag=""; repip=""; repscore=""; inteltag=""; inteltarget=""
  migratealertlevel

  resolvestateroot
  nowepoch=$(date +%s)

  if [ -n "$stateroot" ]; then
    mkdir -m 755 -p "$stateroot"
    local dbfile="$stateroot/seen_alerts.db"
    [ -f "$dbfile" ] || : > "$dbfile"

    lastepoch="$(awk -F'\t' -v k="$key" '$1==k{print $2}' "$dbfile" | tail -n1)"
    [ -z "$lastepoch" ] && lastepoch=0

    if [ "$((nowepoch - lastepoch))" -lt "$cooldownsec" ]; then
      return
    fi

    { awk -F'\t' -v k="$key" '$1!=k' "$dbfile"; printf '%s\t%s\n' "$key" "$nowepoch"; } > "${dbfile}.tmp"
    mv "${dbfile}.tmp" "$dbfile"
  fi

  [ -n "$stateroot" ] && reputationlookup "$kind" "$indicator" "$source"
  astraeaintel "$(astraeatarget "$kind" "$indicator")"

  alertseverity "$kind" "$indicator" "$source" "$detail" "$repscore"
  sevtag="$(echo "$alertsev" | tr 'a-z' 'A-Z')"
  printf '%s %s IOCMON[%s] - WARNING: IOC match (%s): %s matched %s (%s) [%s].\n' "$(date +'%b %d %Y %X')" "$(_GetLAN_HostName_)" "$$" "$kind" "$indicator" "$source" "$detail" "$sevtag" >> "$logfile"

  local raisebanner=1
  [ "$alertlevel" = "critical" ] && [ "$alertsev" != "critical" ] && raisebanner=0

  if [ -n "$stateroot" ]; then
    local alertline
    alertline="$(date +'%b %d %Y %X') | $kind | $indicator | $source | $detail"
    [ -n "$reptag" ] && alertline="$alertline | $reptag"
    [ -n "$inteltag" ] && alertline="$alertline | $inteltag"
    echo "$alertline | sev:$alertsev" >> "$stateroot/ioc_alerts.log"
    rotatelogfile "$stateroot/ioc_alerts.log" "$logsize"

    if [ "$raisebanner" -eq 1 ]; then
      local pendingfile="$stateroot/alert_pending" pendingcount=0
      [ -f "$pendingfile" ] && pendingcount="$(head -n1 "$pendingfile" 2>/dev/null)"
      validateint "$pendingcount" 0 || pendingcount=0
      pendingcount=$((pendingcount + 1))
      { echo "$pendingcount"; echo "$alertline"; } > "$pendingfile"
    fi
  fi

  [ "$raisebanner" -eq 1 ] && queueemailalert "$kind" "$indicator" "$source" "$detail" "$repip" "$inteltarget"
}

# -------------------------------------------------------------------------------------------------------------------------
# migrateiocseverity adds a " | sev:<level>" field, once, to ioc_alerts.log lines written before alerts had a severity

migrateiocseverity()
{
  local file tmp us kind indicator source detail score line count=0
  resolvestateroot
  [ -n "$stateroot" ] || return
  file="$stateroot/ioc_alerts.log"
  [ -s "$file" ] || return
  awk -F' [|] ' 'NF >= 5 && !/ [|] sev:[a-z]*$/ { f = 1; exit } END { exit !f }' "$file" || return
  tmp="$file.sev"
  us="$(printf '\037')"
  awk -F' [|] ' -v us="$us" '
    / [|] sev:[a-z]*$/ || NF < 5 { print "-" us us us us us $0; next }
    {
      n = NF; score = ""
      if ($n ~ /^(TEST )?AbuseIPDB /) { if (match($n, /[0-9]+%/)) score = substr($n, RSTART, RLENGTH - 1); n-- }
      ind = $3; for (i = 4; i <= n - 2; i++) ind = ind " | " $i
      print $2 us ind us $(n - 1) us $n us score us $0
    }
  ' "$file" | while IFS="$us" read -r kind indicator source detail score line; do
    if [ "$kind" = "-" ]; then
      echo "$line"
    else
      alertseverity "$kind" "$indicator" "$source" "$detail" "$score"
      echo "$line | sev:$alertsev"
    fi
  done > "$tmp"
  count="$(grep -c ' | sev:[a-z]*$' "$tmp")"
  mv -f "$tmp" "$file"
  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Added a severity to the IoC detection log ($count line(s) now carry one)." >> "$logfile"
}

# -------------------------------------------------------------------------------------------------------------------------
# checkconntrack reads /proc/net/nf_conntrack, extracting each connection's original-direction src=/dst= IP pair.

checkconntrack()
{
  conntrackchecked=0

  [ "$enableconntrackwatch" -eq 1 ] || return

  resolvefeedsroot
  [ -z "$feedsroot" ] && return

  local ipsfile="$feedsroot/ips.txt" qfipsfile="$feedsroot/qfeeds_ips.txt" pairfile="/tmp/iocmon_ct.$$"
  [ "$enableqfeeds" -eq 1 ] || qfipsfile=""
  [ -s "$ipsfile" ] || [ -s "$qfipsfile" ] || return

  local conntrackfile="/proc/net/nf_conntrack"
  [ -f "$conntrackfile" ] || conntrackfile="/proc/net/ip_conntrack"
  [ -f "$conntrackfile" ] || return

  local pairlist
  pairlist="$(awk '
    {
      src=""; dst=""
      for (i=1; i<=NF; i++) {
        if (src=="" && $i ~ /^src=/) { split($i,a,"="); src=a[2] }
        if (dst=="" && $i ~ /^dst=/) { split($i,a,"="); dst=a[2] }
        if (src!="" && dst!="") break
      }
      if (src!="" && dst!="") print src"|"dst
    }
  ' "$conntrackfile" | sort -u)"
  [ -z "$pairlist" ] && return

  conntrackchecked="$(echo "$pairlist" | wc -l | tr -d ' ')"
  conntracklastcheck=$(date +'%H:%M')

  echo "$pairlist" > "$pairfile"
  set -- "$pairfile"
  [ -s "$ipsfile" ] && set -- "$@" "$ipsfile"
  [ -s "$qfipsfile" ] && set -- "$@" "$qfipsfile"

  awk -F'|' -v pf="$pairfile" -v qf="$qfipsfile" -v exc="$ipexceptions" '
    function toint(ip,  a) { split(ip, a, "."); return (a[1]*16777216)+(a[2]*65536)+(a[3]*256)+a[4] }
    function addmatch(d, sn, fn) {
      if (index(","msrc[d]",", ","sn",") == 0) msrc[d] = (msrc[d]=="" ? sn : msrc[d]","sn)
      if (index(","mfam[d]",", ","fn",") == 0) mfam[d] = (mfam[d]=="" ? fn : mfam[d]","fn)
    }
    function isexcepted(ip,    k, d) {
      if (ip in plainexc) return 1
      for (k = 1; k <= excn; k++) {
        if (iscidr[k]) { d = 2 ^ (32 - cidrmask[k]); if (int(toint(ip) / d) == int(cidrnet[k] / d)) return 1 }
      }
      return 0
    }
    BEGIN {
      excn = split(exc, ea, " ")
      for (k = 1; k <= excn; k++) {
        if (ea[k] == "") continue
        if (index(ea[k], "/") > 0) {
          split(ea[k], pp, "/")
          if ((pp[2] + 0) < 0 || (pp[2] + 0) > 32) continue
          cidrnet[k] = toint(pp[1]); cidrmask[k] = pp[2] + 0; iscidr[k] = 1
        }
        else { plainexc[ea[k]] = 1 }
      }
    }
    FILENAME==pf {
      if (isexcepted($2)) next
      srcs[$2] = (srcs[$2]=="" ? $1 : srcs[$2]","$1)
      if ($2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) dint[$2] = toint($2)
      next
    }
    {
      if (FILENAME==qf) { ind=$0; srcname="qfeeds"; famname="osint-ip" } else { ind=$1; srcname=$2; famname=$3 }
      if (ind == "") next
      if (ind in srcs) { addmatch(ind, srcname, famname); next }
      if (index(ind, "/") == 0) next
      split(ind, p, "/")
      m = p[2] + 0; divisor = 2 ^ (32 - m)
      if (!(m in built)) { built[m] = 1; for (d in dint) { b = m SUBSEP int(dint[d] / divisor); bk[b] = (b in bk ? bk[b] " " d : d) } }
      b = m SUBSEP int(toint(p[1]) / divisor)
      if (b in bk) { nbl = split(bk[b], bl, " "); for (j = 1; j <= nbl; j++) addmatch(bl[j], srcname, famname) }
    }
    END {
      for (d in msrc) { n = split(srcs[d], sl, ","); for (i = 1; i <= n; i++) print sl[i]"|"d"|"msrc[d]"|"mfam[d] }
    }
  ' "$@" | while IFS='|' read -r srcip matchedip source family; do
    raisealert "conntrack" "${srcip}->${matchedip}" "$source" "$family" "$matchedip"
  done
  rm -f "$pairfile"
}

# -------------------------------------------------------------------------------------------------------------------------
# aghlog appends one IOCMON log line: $1 = level (INFO/WARNING), $2 = message

aghlog()
{
  printf '%s %s IOCMON[%s] - %s: %s\n' "$(date +'%b %d %Y %X')" "$(_GetLAN_HostName_)" "$$" "$1" "$2" >> "$logfile"
}

# -------------------------------------------------------------------------------------------------------------------------
# aghjqbin echoes the jq to use: on PATH, else Entware's (a cron/boot PATH may lack /opt/bin)

aghjqbin()
{
  which jq 2>/dev/null && return 0
  [ -x /opt/bin/jq ] && { echo /opt/bin/jq; return 0; }
  return 1
}

# -------------------------------------------------------------------------------------------------------------------------
# aghrunning succeeds if an AdGuard Home process is running

aghrunning()
{
  pidof AdGuardHome >/dev/null 2>&1
}

# -------------------------------------------------------------------------------------------------------------------------
# dnsusesagh succeeds if checkdns should read AdGuard Home instead of dnsmasq (auto: only when AdGuard Home owns port 53)

dnsusesagh()
{
  case "$dnssource" in
    adguardhome) return 0 ;;
    dnsmasq) return 1 ;;
  esac
  aghrunning || return 1
  netstat -lnup 2>/dev/null | awk '$4 ~ /:53$/ { print $NF }' | grep -q 'AdGuardHome' && return 0
  netstat -lnup 2>/dev/null | awk '$4 ~ /:53$/' | grep -q 'dnsmasq' && return 1
  return 0
}

# -------------------------------------------------------------------------------------------------------------------------
# aghyaml echoes the AdGuardHome.yaml in use (from the running process's -c, else the usual paths)

aghyaml()
{
  local pid f
  pid="$(pidof AdGuardHome 2>/dev/null | awk '{ print $1 }')"
  if [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ]; then
    f="$(tr '\000' '\n' < "/proc/$pid/cmdline" | awk 'p { print; exit } $0 == "-c" || $0 == "--config" { p = 1 }')"
    [ -n "$f" ] && [ "${f#/}" = "$f" ] && f="$(readlink "/proc/$pid/cwd" 2>/dev/null)/$f"
    [ -f "$f" ] && { echo "$f"; return; }
  fi
  for f in $aghyamlpaths; do [ -f "$f" ] && { echo "$f"; return; }; done
}

# -------------------------------------------------------------------------------------------------------------------------
# aghapiurl echoes the API base URL: the backup's when aghslot=2, else $aghurl, else the yaml's http.address (or bind_host/bind_port)

aghapiurl()
{
  local y addr host port
  [ "$aghslot" = "2" ] && { echo "${aghurl2%/}"; return; }
  [ -n "$aghurl" ] && { echo "${aghurl%/}"; return; }
  y="$(aghyaml)"
  if [ -n "$y" ]; then
    addr="$(awk '/^http:/ { h = 1; next } h && /^[^ ]/ { h = 0 } h && $1 == "address:" { print $2; exit }' "$y")"
    if [ -z "$addr" ]; then
      host="$(awk '$1 == "bind_host:" { print $2; exit }' "$y")"; port="$(awk '$1 == "bind_port:" { print $2; exit }' "$y")"
      [ -n "$port" ] && addr="${host:-0.0.0.0}:$port"
    fi
  fi
  addr="${addr:-0.0.0.0:3000}"
  host="${addr%:*}"; port="${addr##*:}"
  case "$host" in ""|0.0.0.0|"[::]"|::) host="127.0.0.1" ;; esac
  echo "http://$host:$port"
}

# -------------------------------------------------------------------------------------------------------------------------
# aghcurl $1=path $2=body file [curl args...] calls the API with the current instance's login (on stdin) and prints the HTTP status

aghcurl()
{
  local p="$1" o="$2"; shift 2
  aghhaslogin || { echo "000"; return 0; }
  [ -n "$aghurl2" ] && set -- "$@" --connect-timeout 5
  printf 'user = "%s"\n' "$(aghdecode | sed 's/[\\"]/\\&/g')" | curl -s -L -k --max-time 15 -K - -o "$o" -w '%{http_code}' "$(aghapiurl)$p" "$@" 2>/dev/null
  return 0
}

# -------------------------------------------------------------------------------------------------------------------------
# aghencode $1=text echoes it base64-encoded with openssl, on one line

aghencode()
{
  printf '%s' "$1" | openssl base64 -A 2>/dev/null
}

# -------------------------------------------------------------------------------------------------------------------------
# aghdecode echoes the plain user:password of the current instance (aghcred, or aghcred2 when aghslot=2)

aghdecode()
{
  local c="$aghcred"
  [ "$aghslot" = "2" ] && c="$aghcred2"
  [ -n "$c" ] && printf '%s\n' "$c" | openssl base64 -d -A 2>/dev/null
}

# -------------------------------------------------------------------------------------------------------------------------
# aghhaslogin succeeds if the current login decodes to user:password; curl waits at the terminal for a password without one

aghhaslogin()
{
  case "$(aghdecode)" in ?*:*) return 0 ;; esac
  return 1
}

# -------------------------------------------------------------------------------------------------------------------------
# aghhasbackup succeeds if a backup instance has both an address and a usable login

aghhasbackup()
{
  [ -n "$aghurl2" ] || return 1
  (aghslot=2; aghhaslogin)
}

# -------------------------------------------------------------------------------------------------------------------------
# aghanylogin succeeds if at least one AdGuard Home instance can be tried

aghanylogin()
{
  aghhaslogin || aghhasbackup
}

# -------------------------------------------------------------------------------------------------------------------------
# aghnormurl $1=typed address echoes it as a clean base URL (http:// added if missing), or returns 1 if unusable

aghnormurl()
{
  local u="$1"
  case "$u" in *[!]A-Za-z0-9.:/_[-]*) return 1 ;; esac
  case "$u" in http://*|https://*) ;; *://*) return 1 ;; *) u="http://$u" ;; esac
  case "${u#*://}" in ""|:*|/*) return 1 ;; esac
  echo "${u%/}"
}

# -------------------------------------------------------------------------------------------------------------------------
# aghmigrateauth moves a login from the old agh.auth file into aghcred, then deletes the file

aghmigrateauth()
{
  local login
  [ -f "$aghauthfile" ] || return
  if [ -z "$aghcred" ]; then
    login="$(sed -n 's/^user = "\(.*\)"$/\1/p' "$aghauthfile" | sed 's/\\\(.\)/\1/g')"
    [ -n "$login" ] && aghcred="$(aghencode "$login")"
    [ -n "$aghcred" ] || { aghlog "WARNING" "The AdGuard Home login in $aghauthfile could not be moved into iocmon.cfg - the file was kept."; return; }
    saveconfig
  fi
  rm -f "$aghauthfile"
  aghlog "INFO" "AdGuard Home login moved from $aghauthfile into iocmon.cfg."
}

# -------------------------------------------------------------------------------------------------------------------------
# aghstatus echoes "ok" or a one-line reason: no jq, no login, API unreachable, bad login, query log off

aghstatus()
{
  local code jq b="/tmp/iocmon_aghst.$$" item=11
  [ "$aghslot" = "2" ] && item=13
  jq="$(aghjqbin)" || { echo "jq is not installed (Entware: opkg install jq)"; return 1; }
  aghhaslogin || { echo "no AdGuard Home login set (Advanced Settings - DNS Watch, item $item)"; return 1; }
  [ "$aghslot" = "2" ] && [ -z "$aghurl2" ] && { echo "no backup AdGuard Home address set (Advanced Settings - DNS Watch, item 15)"; return 1; }
  code="$(aghcurl /control/querylog/config "$b")"
  [ "$code" = "404" ] && code="$(aghcurl /control/querylog_info "$b")"
  case "$code" in
    200) ;;
    401|403) rm -f "$b"; echo "AdGuard Home rejected the login (HTTP $code)"; return 1 ;;
    000|"") rm -f "$b"; echo "AdGuard Home API not reachable at $(aghapiurl)"; return 1 ;;
    *) rm -f "$b"; echo "AdGuard Home API error (HTTP $code)"; return 1 ;;
  esac
  if ! "$jq" -e '.enabled == true' "$b" >/dev/null 2>&1; then
    rm -f "$b"; echo "AdGuard Home's query log is turned off (Settings - DNS settings - Query logs)"; return 1
  fi
  if "$jq" -e '.anonymize_client_ip == true' "$b" >/dev/null 2>&1; then
    rm -f "$b"; echo "ok, but client IPs are anonymized in AdGuard Home, so alerts can't name the device"; return 0
  fi
  rm -f "$b"; echo "ok"
}

# -------------------------------------------------------------------------------------------------------------------------
# aghjq turns one query-log page into M| (page meta), Q| (domain|client|epoch|blocked) and R| (domain|ip) lines; no regex (no Oniguruma)
aghjq='
def key: . as $t
  | (if ($t | endswith("Z")) then { b: $t[19:-1], z: 0 }
     else { b: $t[19:-6],
            z: ((($t[-5:-3] | tonumber) * 3600 + ($t[-2:] | tonumber) * 60) * (if $t[-6:-5] == "-" then -1 else 1 end)) } end) as $p
  | ((($t[0:19] + "Z") | fromdateiso8601) - $p.z) as $s
  | (if ($p.b | startswith(".")) then $p.b[1:] else "" end) as $f
  | ("0000000000" + ($s | floor | tostring))[-10:] + (($f + "000000000")[:9]);
def blocked: (.reason // "") | (startswith("Filtered") and . != "FilteredSafeSearch");
(.data // []) as $d
| ($d | map(try (.time | key) catch "0")) as $k
| "M|\($d | length)|\($k | min // "")|\($k | max // "")|\($d[-1].time // "")",
  ($d[] | select((try (.time | key) catch "0") > $cur)
   | ((.question.name // "") | ascii_downcase | rtrimstr(".")) as $n
   | select($n != "")
   | "Q|\($n)|\(.client // "")|\((try (.time | key) catch "0")[0:10] | tonumber)|\(if blocked then 1 else 0 end)",
     (.answer // [] | .[] | select(.type == "A" or .type == "AAAA") | "R|\($n)|\(.value)"))
'

# -------------------------------------------------------------------------------------------------------------------------
# aghquerypairs $1=output file writes the domain|client pairs logged since the cursor; 1 = API error, 2 = first run

aghquerypairs()
{
  local outfile="$1" tmp="/tmp/iocmon_agh.$$" cur="" curfile="" newest="" older="" pages=0 meta n oldk newk oldraw out code done=0 jq warned="$aghapiwarned"
  [ "$aghslot" = "2" ] && warned="$aghapiwarned2"
  aghqueries=0; aghskippedblocked=0
  : > "$outfile"
  if ! jq="$(aghjqbin)"; then
    [ "$aghjqwarned" = "1" ] || aghlog "WARNING" "DNS watch needs jq to read AdGuard Home's query log - install it from the Entware components menu (opkg install jq)."
    aghjqwarned=1; return 1
  fi
  aghjqwarned=0
  [ -n "$stateroot" ] && curfile="$stateroot/agh_cursor"
  if [ -n "$curfile" ] && [ -f "$curfile" ]; then cur="$(cat "$curfile" 2>/dev/null)"; else cur="${aghcursorcache:-}"; fi
  [ "$aghslot" = "2" ] && [ -n "$aghcursorcache2" ] && cur="$aghcursorcache2"
  [ "${#cur}" -eq 19 ] || cur=""
  mkdir -p "$tmp"; : > "$tmp/all"; : > "$outfile"

  while [ "$pages" -lt "$aghmaxpages" ]; do
    if [ -n "$older" ]; then
      code="$(aghcurl /control/querylog "$tmp/resp" -G --data-urlencode "limit=$aghpagesize" --data-urlencode "response_status=all" --data-urlencode "older_than=$older")"
    else
      code="$(aghcurl /control/querylog "$tmp/resp" -G --data-urlencode "limit=$aghpagesize" --data-urlencode "response_status=all")"
    fi
    if [ "$code" != "200" ]; then
      [ "$warned" != "$code" ] && aghlog "WARNING" "DNS watch could not read AdGuard Home's query log (HTTP ${code:-none} from $(aghapiurl)) - check Advanced Settings - DNS Watch."
      if [ "$aghslot" = "2" ]; then aghapiwarned2="$code"; else aghapiwarned="$code"; fi
      rm -rf "$tmp"; return 1
    fi
    [ -n "$warned" ] && aghlog "INFO" "DNS watch can read AdGuard Home's query log again ($(aghapiurl))."
    warned=""
    if [ "$aghslot" = "2" ]; then aghapiwarned2=""; else aghapiwarned=""; fi
    "$jq" -r --arg cur "$cur" "$aghjq" "$tmp/resp" > "$tmp/page" 2>"$tmp/err"
    meta="$(head -n 1 "$tmp/page")"
    case "$meta" in
      M\|*) ;;
      *) aghlog "WARNING" "DNS watch could not parse AdGuard Home's query log reply ($(head -c 200 "$tmp/err" "$tmp/resp" 2>/dev/null | tr '\n' ' '))."
         rm -rf "$tmp"; return 1 ;;
    esac
    n="$(echo "$meta" | cut -d'|' -f2)"; oldk="$(echo "$meta" | cut -d'|' -f3)"; newk="$(echo "$meta" | cut -d'|' -f4)"; oldraw="$(echo "$meta" | cut -d'|' -f5)"
    if [ "$pages" -eq 0 ]; then
      newest="$newk"
      if [ "${n:-0}" -gt 0 ] && [ "${#newest}" -ne 19 ]; then
        aghlog "WARNING" "DNS watch could not read the timestamps in AdGuard Home's query log (newest: $(echo "$meta" | cut -d'|' -f5))."
        rm -rf "$tmp"; return 1
      fi
    fi
    sed 1d "$tmp/page" >> "$tmp/all"
    pages=$((pages + 1))
    [ -z "$cur" ] && { done=1; break; }
    [ "${n:-0}" -lt "$aghpagesize" ] && { done=1; break; }
    awk -v a="k$oldk" -v b="k$cur" 'BEGIN { exit !(a <= b) }' && { done=1; break; }
    [ -n "$oldraw" ] || { done=1; break; }
    older="$oldraw"
  done
  [ "$done" -eq 0 ] && aghlog "WARNING" "DNS watch read $pages pages ($((pages * aghpagesize)) queries) of AdGuard Home's log this cycle and stopped; older queries since the last cycle were not checked. Raise aghmaxpages or lower timerloop."

  if [ -n "$newest" ] && [ "$aghslot" = "2" ]; then
    aghcursorcache2="$newest"
  elif [ -n "$newest" ]; then
    if [ -n "$curfile" ]; then echo "$newest" > "$curfile"; fi
    aghcursorcache="$newest"
  fi
  if [ -z "$cur" ]; then
    aghlog "INFO" "DNS watch is reading AdGuard Home's query log ($(aghapiurl)), starting from now."
    rm -rf "$tmp"; return 2
  fi

  grep '^R|' "$tmp/all" | cut -d'|' -f2- >> "$aghreplyfile"
  [ "$(wc -l < "$aghreplyfile" 2>/dev/null || echo 0)" -gt 20000 ] && { tail -n 10000 "$aghreplyfile" > "$aghreplyfile.t" && mv -f "$aghreplyfile.t" "$aghreplyfile"; }

  aghqueries="$(grep -c '^Q|' "$tmp/all")"
  aghskippedblocked="$(grep -c '^Q|.*|1$' "$tmp/all")"
  if [ "$aghincludeblocked" = "1" ]; then grep '^Q|' "$tmp/all"; else grep '^Q|.*|0$' "$tmp/all"; fi | cut -d'|' -f2,3,4 > "$outfile.times"
  cut -d'|' -f1,2 "$outfile.times" | sort -u > "$outfile"
  [ "$aghincludeblocked" = "1" ] && aghskippedblocked=0
  rm -rf "$tmp"
  return 0
}

# -------------------------------------------------------------------------------------------------------------------------
# aghreadlog $1=output file reads the primary, then the backup if that fails, and sets aghfailover: 0 primary, 1 backup, 2 neither

aghreadlog()
{
  local rc=1 state=0
  aghslot=1
  aghhaslogin && { aghquerypairs "$1"; rc=$?; }
  if [ "$rc" -eq 1 ] && aghhasbackup; then
    aghslot=2
    aghquerypairs "$1"; rc=$?
    aghslot=1
    state=2; [ "$rc" -eq 1 ] || state=1
  fi
  if [ "$state" != "$aghfailover" ]; then
    case "$state" in
      0) aghlog "INFO" "DNS watch is back on the primary AdGuard Home ($(aghapiurl))." ;;
      1) aghlog "WARNING" "DNS watch switched to the backup AdGuard Home (${aghurl2%/}): the primary ($(aghapiurl)) could not be read." ;;
      2) aghlog "WARNING" "DNS watch could not read the primary ($(aghapiurl)) or the backup AdGuard Home (${aghurl2%/})." ;;
    esac
    aghfailover="$state"
  fi
  [ "$state" -eq 0 ] && aghcursorcache2=""
  return "$rc"
}

# -------------------------------------------------------------------------------------------------------------------------
# aghreplyip $1=domain echoes the last public IP AdGuard Home answered for $1 or a subdomain (never resolves itself)

aghreplyip()
{
  [ -n "$1" ] && [ -f "$aghreplyfile" ] || return
  awk -F'|' -v d="$1" '
    function usable(v) {
      if (v ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return (v !~ /^(0|10|127)\./ && v !~ /^192\.168\./ && v !~ /^172\.(1[6-9]|2[0-9]|3[01])\./)
      return (v ~ /^[23][0-9a-fA-F]*:[0-9a-fA-F:]+$/)
    }
    ($1 == d || substr($1, length($1) - length(d)) == "." d) && usable($2) { ip = $2 }
    END { if (ip != "") print ip }' "$aghreplyfile"
}

# -------------------------------------------------------------------------------------------------------------------------
# dnsquerylogenabled/enablednsquerylogging manage the one-time opt-in dnsmasq change checkdns() depends on

dnsquerylogenabled()
{
  grep -qE '^[[:space:]]*log-queries([[:space:]]*$|=)' /jffs/configs/dnsmasq.conf.add 2>/dev/null && return 0
  dnsquerylogactiveinetc
}

# -------------------------------------------------------------------------------------------------------------------------
# dnsquerylogactiveinetc succeeds if another script already activated log-queries directly in /etc/dnsmasq.conf

dnsquerylogactiveinetc()
{
  grep -qE '^[[:space:]]*log-queries([[:space:]]*$|=)' /etc/dnsmasq.conf 2>/dev/null
}

# -------------------------------------------------------------------------------------------------------------------------
# dnslogverified succeeds if file $1 exists and its recent tail contains dnsmasq query lines.

dnslogverified()
{
  [ -f "$1" ] && tail -n 500 "$1" 2>/dev/null | grep -qE 'dnsmasq.*query\['
}

# -------------------------------------------------------------------------------------------------------------------------
# dnssyslogngfiles echoes every plain-path file() destination in a syslog-ng config that mentions dnsmasq.

dnssyslogngfiles()
{
  local f
  for f in /opt/etc/syslog-ng.d/* /opt/etc/syslog-ng.conf /opt/etc/syslog-ng/syslog-ng.conf; do
    [ -f "$f" ] || continue
    grep -q 'dnsmasq' "$f" 2>/dev/null || continue
    sed -n 's/.*file("\([^"$]*\)".*/\1/p' "$f" 2>/dev/null
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# dnslogfacilitypath echoes the active log-facility= path in /etc/dnsmasq.conf, or nothing if none is set.

dnslogfacilitypath()
{
  grep -E '^log-facility=' /etc/dnsmasq.conf 2>/dev/null | tail -n1 | cut -d= -f2-
}

# -------------------------------------------------------------------------------------------------------------------------
# resolvednslogfile sets $dnslogresolved/$dnslogreason to the file holding dnsmasq's query lines: manual path, log-facility, then a content-verified auto-detect.

resolvednslogfile()
{
  local facility cand now
  now=$(date +%s)

  if [ -n "$dnslogpath" ] && [ -f "$dnslogpath" ]; then
    dnslogresolved="$dnslogpath"; dnslogreason="manual setting"
    return
  fi

  facility="$(dnslogfacilitypath)"
  if [ -n "$facility" ] && [ -f "$facility" ]; then
    dnslogresolved="$facility"; dnslogreason="dnsmasq log-facility"
    return
  fi

  if [ -n "$dnslogautofile" ] && [ -f "$dnslogautofile" ] && [ "$((now - ${dnslogautotime:-0}))" -lt 300 ]; then
    dnslogresolved="$dnslogautofile"; dnslogreason="$dnslogautoreason"
    return
  fi

  dnslogautofile="/tmp/syslog.log"; dnslogautoreason="syslog"
  if ! dnslogverified /tmp/syslog.log; then
    dnslogautoreason="syslog (no dnsmasq query lines found anywhere)"
    for cand in $(dnssyslogngfiles) $dnslogknownpaths; do
      if dnslogverified "$cand"; then
        dnslogautofile="$cand"; dnslogautoreason="auto-detected dnsmasq log"
        break
      fi
    done
  fi

  if [ "$dnslogautofile" = "/tmp/syslog.log" ] && [ "$dnslogautoreason" != "syslog" ]; then
    dnslognonecount=$((${dnslognonecount:-0} + 1))
  else
    dnslognonecount=0
  fi

  dnslogautotime="$now"
  dnslogresolved="$dnslogautofile"; dnslogreason="$dnslogautoreason"
}

# -------------------------------------------------------------------------------------------------------------------------
# indnsexceptionlist tests $1 (a domain) for exact membership in $dnsexceptions

indnsexceptionlist()
{
  indomainlist "$1" "$dnsexceptions"
}

# -------------------------------------------------------------------------------------------------------------------------
# indomainlist succeeds when domain $1 equals, or is a subdomain of, any entry in the space-separated list $2

indomainlist()
{
  local domain="$1" ex
  for ex in $2; do
    case "$domain" in
      "$ex"|*".$ex") return 0 ;;
    esac
  done
  return 1
}

# -------------------------------------------------------------------------------------------------------------------------
# basedomain reduces $1 to its last two dot-separated labels (same approximation checkdns's tunnel heuristic uses)

basedomain()
{
  echo "$1" | awk -F. '{n=NF; if (n>=2) print $(n-1)"."$n; else print $0}'
}

enablednsquerylogging()
{
  if dnsquerylogactiveinetc; then
    echo -e "${CGreen}log-queries is already active in /etc/dnsmasq.conf (likely set by another script) - nothing added to dnsmasq.conf.add, no restart needed.${CClear}"
    return 0
  fi

  if dnsquerylogenabled; then
    echo -e "${CGreen}DNS query logging is already enabled.${CClear}"
    return 0
  fi

  echo "log-queries" >> /jffs/configs/dnsmasq.conf.add
  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Enabled dnsmasq query logging (log-queries) via dnsmasq.conf.add." >> "$logfile"
  service restart_dnsmasq >/dev/null 2>&1
  echo ""
  echo -e "${CGreen}DNS query logging enabled and dnsmasq restarted.${CClear}"
}

# -------------------------------------------------------------------------------------------------------------------------
# dnsquerylogowncount $1=file counts its active log-queries lines, leaving out the one Astraea adds under its own marker line

dnsquerylogowncount()
{
  awk -v m="$astraealogmark" '$0 == m { a = 1; next } /^[[:space:]]*log-queries([[:space:]]*$|=)/ && !a { n++ } { a = 0 } END { print n + 0 }' "$1"
}

# -------------------------------------------------------------------------------------------------------------------------
# disablednsquerylogging removes any active log-queries line from dnsmasq.conf.add and restarts dnsmasq, only if one was actually there.

disablednsquerylogging()
{
  local conf="/jffs/configs/dnsmasq.conf.add" before after astraeanote=""

  [ -f "$conf" ] || return 0
  grep -qxF "$astraealogmark" "$conf" && astraeanote=" Astraea's own log-queries line was kept, so dnsmasq still logs queries for Astraea."

  before="$(dnsquerylogowncount "$conf")"
  if [ "$before" -eq 0 ]; then
    echo -e "${CGreen}No active log-queries line of IOCMON's was found in dnsmasq.conf.add - nothing to remove.${astraeanote}${CClear}"
    return 0
  fi

  awk -v m="$astraealogmark" '$0 == m { print; a = 1; next } a && /^[[:space:]]*log-queries([[:space:]]*$|=)/ { print; a = 0; next } { a = 0 } !/^[[:space:]]*log-queries([[:space:]]*$|=)/' "$conf" > "$conf.iocmon" && cat "$conf.iocmon" > "$conf"
  rm -f "$conf.iocmon"
  after="$(dnsquerylogowncount "$conf")"

  if [ "$after" -ne 0 ]; then
    echo -e "${CRed}ERROR: Could not remove log-queries from dnsmasq.conf.add - remove it by hand, then run: service restart_dnsmasq${CClear}"
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - ERROR: Failed to remove log-queries from dnsmasq.conf.add." >> "$logfile"
    return 1
  fi

  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Removed dnsmasq query logging (log-queries) from dnsmasq.conf.add." >> "$logfile"
  service restart_dnsmasq >/dev/null 2>&1
  echo -e "${CGreen}DNS watch turned off: removed log-queries from dnsmasq.conf.add and restarted dnsmasq.${astraeanote}${CClear}"
}

# -------------------------------------------------------------------------------------------------------------------------
# enablednsfilelogging points dnsmasq's own query log at a plain file via log-facility=, bypassing syslog - a workaround for a router where dnsmasq can't reach syslog at all.

enablednsfilelogging()
{
  local existing targetfile

  existing="$(dnslogfacilitypath)"
  if [ -n "$existing" ]; then
    echo -e "${CGreen}log-facility is already set to ${existing} (likely by another script) - IOCMON will read queries from there; nothing added.${CClear}"
    return 0
  fi

  resolvestateroot
  if [ -z "$stateroot" ]; then
    echo -e "${CRed}No feed-storage location is resolved yet - cannot pick a log file path. Try again once a drive is configured.${CClear}"
    return 1
  fi

  targetfile="$stateroot/dnsmasq_queries.log"
  mkdir -m 755 -p "$stateroot"
  : > "$targetfile"
  echo "log-facility=$targetfile" >> /jffs/configs/dnsmasq.conf.add
  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Forced file-based dnsmasq query logging to $targetfile via dnsmasq.conf.add." >> "$logfile"
  service restart_dnsmasq >/dev/null 2>&1
  echo -e "${CGreen}dnsmasq will now log queries directly to ${targetfile}, bypassing syslog.${CClear}"
}

# -------------------------------------------------------------------------------------------------------------------------
# disablednsfilelogging removes log-facility= from dnsmasq.conf.add, but only if it still points at IOCMON's own file - never another script's.

disablednsfilelogging()
{
  local conf="/jffs/configs/dnsmasq.conf.add" ourfile wantline

  resolvestateroot
  ourfile="${stateroot:+$stateroot/dnsmasq_queries.log}"

  if [ -z "$ourfile" ] || [ "$(dnslogfacilitypath)" != "$ourfile" ]; then
    echo -e "${CGreen}No IOCMON-owned log-facility line was found - nothing to remove.${CClear}"
    return 0
  fi

  [ -f "$conf" ] || return 0
  wantline="log-facility=$ourfile"

  if ! grep -qxF "$wantline" "$conf"; then
    echo -e "${CGreen}No IOCMON-owned log-facility line was found in dnsmasq.conf.add - nothing to remove.${CClear}"
    return 0
  fi

  grep -vxF "$wantline" "$conf" > "${conf}.tmp"
  mv "${conf}.tmp" "$conf"

  if grep -qxF "$wantline" "$conf"; then
    echo -e "${CRed}ERROR: Could not remove log-facility from dnsmasq.conf.add - remove it by hand, then run: service restart_dnsmasq${CClear}"
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - ERROR: Failed to remove log-facility from dnsmasq.conf.add." >> "$logfile"
    return 1
  fi

  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Removed forced file-based dnsmasq query logging (log-facility) from dnsmasq.conf.add." >> "$logfile"
  service restart_dnsmasq >/dev/null 2>&1
  echo -e "${CGreen}File-based query logging turned off: removed log-facility from dnsmasq.conf.add and restarted dnsmasq.${CClear}"
}

# -------------------------------------------------------------------------------------------------------------------------
# rotatednsfilelog rotates $1 once it reaches dnsquerylogmaxkb, keeping dnsquerylogkeep generations, then restarts dnsmasq so it reopens a fresh file.

rotatednsfilelog()
{
  local file="$1" maxbytes size gen

  [ -f "$file" ] || return 0
  size="$(filesizeof "$file")"
  maxbytes=$((dnsquerylogmaxkb * 1024))
  [ "${size:-0}" -lt "$maxbytes" ] && return 0

  gen="$dnsquerylogkeep"
  [ -f "${file}.${gen}" ] && rm -f "${file}.${gen}"
  while [ "$gen" -gt 1 ]; do
    [ -f "${file}.$((gen - 1))" ] && mv -f "${file}.$((gen - 1))" "${file}.${gen}"
    gen=$((gen - 1))
  done
  mv -f "$file" "${file}.1"
  : > "$file"
  service restart_dnsmasq >/dev/null 2>&1
  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Rotated dnsmasq query log ($file reached ${dnsquerylogmaxkb}KB) and restarted dnsmasq to reopen it." >> "$logfile"
}

# -------------------------------------------------------------------------------------------------------------------------
# syslogresumepoint echoes the line number to resume after in $1, using the saved count and last-line anchor so pruning/rotation can't trigger a full replay.

syslogresumepoint()
{
  local file="$1" lastcount="$2" anchor="$3" linecount="$4" found

  if [ "$lastcount" -gt 0 ] && [ "$lastcount" -le "$linecount" ]; then
    if [ -z "$anchor" ] || [ "$(sed -n "${lastcount}p" "$file")" = "$anchor" ]; then
      echo "$lastcount"
      return
    fi
  fi

  if [ -n "$anchor" ]; then
    found="$(grep -nxF -- "$anchor" "$file" | tail -n 1 | cut -d: -f1)"
    if [ -n "$found" ]; then
      echo "$found"
      return
    fi
  fi

  echo 0
}

# -------------------------------------------------------------------------------------------------------------------------
# authnewlines reads matching log lines on stdin, echoes only those not yet recorded in ledger $1 (multiplicity-aware), then updates the ledger.

authnewlines()
{
  local ledger="$1" tmpbase="/tmp/iocmon_authseen.$$"

  [ -f "$ledger" ] || : > "$ledger"
  cat > "${tmpbase}.cur"
  : > "${tmpbase}.out"
  : > "${tmpbase}.new"

  awk -v lp="$ledger" -v outf="${tmpbase}.out" -v newf="${tmpbase}.new" '
    FILENAME==lp { i=index($0,"\t"); if (i>0) seen[substr($0,i+1)]=substr($0,1,i-1)+0; next }
    { if (!($0 in cur)) order[++n]=$0; cur[$0]++ }
    END {
      for (k=1; k<=n; k++) {
        l=order[k]; prev=(l in seen)?seen[l]:0; c=cur[l]
        for (j=prev; j<c; j++) print l > outf
        print ((c>prev)?c:prev) "\t" l > newf
      }
    }' "$ledger" "${tmpbase}.cur"

  if [ "$(cat "${tmpbase}.new")" != "$(cat "$ledger")" ]; then
    mv "${tmpbase}.new" "$ledger"
  fi

  cat "${tmpbase}.out"
  rm -f "${tmpbase}.cur" "${tmpbase}.out" "${tmpbase}.new"
}

# -------------------------------------------------------------------------------------------------------------------------
# routeraddrs prints loopback and every address on the router's own interfaces, as Astraea defines them

routeraddrs()
{
  echo "127.0.0.1"; echo "::1"
  ip -o addr show 2>/dev/null | awk '{ a = $4; sub(/\/.*/, "", a); print a }'
}

# -------------------------------------------------------------------------------------------------------------------------
# selfqfiles prints the Kairos/Astraea files listing the router's own lookups that exist, are not empty and (Kairos) whose add-on is running

selfqfiles()
{
  local f
  for f in $selfqpaths; do
    [ -s "$f" ] || continue
    case "$f" in "${kairosstatusfile%/*}"/*) kairosactive || continue ;; esac
    echo "$f"
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# kairosactive succeeds while Kairos's state is known: its status file written in the last 3 minutes, or for an older Kairos, kairos_time in nvram

kairosactive()
{
  local k v t="" updated=""
  if [ -f "$kairosstatusfile" ]; then
    while IFS='=' read -r k v; do
      case "$k" in
        time) t="$v" ;;
        updated) updated="$v" ;;
      esac
    done < "$kairosstatusfile"
    validateint "$updated" 0 || return 1
    [ $(( $(date +%s) - updated )) -le 180 ] || return 1
  else
    nvramget kairos_time || return 1
    t="$nvramval"
  fi
  case "$t" in booting|synced|degraded) return 0 ;; esac
  return 1
}

# -------------------------------------------------------------------------------------------------------------------------
# dnslogtimes reads dnsmasq log lines on stdin and prints name|src|epoch for router-sourced queries ($1 = router addresses)

dnslogtimes()
{
  set -- "$1" $(date +'%Y %m %d %H %M %S') "$(date +%s)"
  awk -v r=" $(echo $1) " -v Y="$2" -v M="$3" -v D="$4" -v h="$5" -v mi="$6" -v s="$7" -v now="$8" '
    function dn(y, m, d,   era, yoe, doy, doe) {
      if (m <= 2) y -= 1
      era = (y >= 0 ? y : y - 399); era = int(era / 400)
      yoe = y - era * 400
      doy = int((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1
      doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
      return era * 146097 + doe - 719468
    }
    function hms(t,   a) { if (split(t, a, ":") < 3) return -1; return a[1] * 3600 + a[2] * 60 + int(a[3]) }
    BEGIN {
      n = split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", names, " "); for (i = 1; i <= n; i++) mon[names[i]] = i
      off = dn(Y + 0, M + 0, D + 0) * 86400 + h * 3600 + mi * 60 + s - now
    }
    {
      name = ""; src = ""
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^query\[[A-Za-z]+\]$/) name = $(i + 1)
        if ($i == "from" && (i + 1) <= NF) src = $(i + 1)
      }
      if (name == "" || src !~ /^[0-9A-Fa-f.:]+$/) next
      name = tolower(name); gsub(/[^a-z0-9._-]/, "_", name)
      a = src; sub(/^::ffff:/, "", a)
      if (index(r, " " a " ") == 0) next
      e = 0
      if (($1 in mon) && $2 ~ /^[0-9]+$/ && (t = hms($3)) >= 0) {
        y = Y + 0
        if (mon[$1] > M + 0 || (mon[$1] == M + 0 && $2 + 0 > D + 0)) y--
        e = dn(y, mon[$1], $2 + 0) * 86400 + t - off
      } else if ($1 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/) {
        t = hms(substr($1, 12, 8)); z = substr($1, 20); sub(/^\.[0-9]+/, "", z)
        e = dn(substr($1, 1, 4) + 0, substr($1, 6, 2) + 0, substr($1, 9, 2) + 0) * 86400 + t
        if (z == "Z") e = e
        else if (z ~ /^[+-][0-9][0-9]:?[0-9][0-9]$/) { gsub(/:/, "", z); e -= (substr(z, 1, 1) == "-" ? -1 : 1) * (substr(z, 2, 2) * 3600 + substr(z, 4, 2) * 60) }
        else e -= off
      }
      print name "|" src "|" e
    }'
}

# -------------------------------------------------------------------------------------------------------------------------
# selfqmatch $1=name|src|epoch file prints domain|src|tool for router lookups that were Kairos's or Astraea's own, and RECENT if one under 10s old was not

selfqmatch()
{
  local tf="$1" files
  files="$(selfqfiles)"
  awk -F'|' -v r=" $(routeraddrs | tr '\n' ' ') " -v now="$(date +%s)" -v lo="$dnsselfqfloor" -v tf="$tf" '
    FILENAME != tf {
      n = tolower($1); c[n]++; ep[n, c[n]] = $3 + 0; tl[n, c[n]] = (FILENAME ~ /astraea/ ? "Astraea" : "Kairos")
      next
    }
    {
      a = $2; sub(/^::ffff:/, "", a)
      if (index(r, " " a " ") == 0) next
      n = tolower($1); sub(/\.$/, "", n); e = $3 + 0; k = $1 "|" $2; seen[k] = 1; hit = ""
      for (i = 1; i <= c[n]; i++) {
        d = ep[n, i]
        if (e > 0 ? (d - e <= 60 && e - d <= 60) : (d >= lo)) { hit = tl[n, i]; break }
      }
      if (hit == "") { bad[k] = 1; if (e > 0 && now - e < 10) recent = 1 }
      else if (!(k in who)) who[k] = hit
    }
    END {
      for (k in seen) if (!(k in bad)) print k "|" who[k]
      if (recent) print "RECENT"
    }' $files "$tf"
}

# -------------------------------------------------------------------------------------------------------------------------
# selfqfilter $1=pairs file $2=name|src|epoch file splits off the router's Kairos/Astraea lookups into $1.self, keeping device pairs in $1

selfqfilter()
{
  local pairs="$1" times="$2" out
  : > "$pairs.self"
  dnsselfcount=0
  [ -n "$(selfqfiles)" ] && [ -s "$times" ] || return 0
  [ -n "$dnsselfqfloor" ] || dnsselfqfloor=$(( $(date +%s) - 7200 ))
  out="$(selfqmatch "$times")"
  case "$out" in
    *RECENT*) sleep 3; out="$(selfqmatch "$times")" ;;
  esac
  dnsselfqfloor=$(( $(date +%s) - 60 ))
  echo "$out" | grep -v '^RECENT$' | grep . > "$pairs.self"
  [ -s "$pairs.self" ] || return 0
  dnsselfcount="$(wc -l < "$pairs.self" | tr -d ' ')"
  awk -F'|' 'NR == FNR { s[$1 "|" $2] = 1; next } !(($1 "|" $2) in s)' "$pairs.self" "$pairs" > "$pairs.dev"
  mv -f "$pairs.dev" "$pairs"
}

# -------------------------------------------------------------------------------------------------------------------------
# selfqinfo $1=name $2=message logs one INFO line about a router lookup set aside, at most once per name every 6 hours

selfqinfo()
{
  local now last
  now=$(date +%s)
  last="$(awk -v n="$1" '$1 == n { print $2 }' "$selfqseenfile" 2>/dev/null | tail -n 1)"
  [ -n "$last" ] && [ $((now - last)) -lt 21600 ] && return 0
  { awk -v n="$1" -v c=$((now - 21600)) '$1 != n && $2 >= c' "$selfqseenfile" 2>/dev/null; echo "$1 $now"; } > "$selfqseenfile.t"
  mv -f "$selfqseenfile.t" "$selfqseenfile"
  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: $2" >> "$logfile"
}

# -------------------------------------------------------------------------------------------------------------------------
# checkdns tails new DNS query log lines since the last check

checkdns()
{
  dnschecked=0
  dnsqueriedcount=0
  dnsselfcount=0

  [ "$enablednswatch" -eq 1 ] || return

  local aghmode=0
  dnsusesagh && aghmode=1

  if [ "$aghmode" -eq 1 ] && ! aghanylogin; then
    aghfailover=0
    [ "$aghloginwarned" = "1" ] || aghlog "WARNING" "DNS watch is skipped: AdGuard Home is the DNS source but no login is set. Add it under Configuration Menu ${advsettingsmenunum}.2, item 12."
    aghloginwarned=1
    dnslogshort="Add the login under Configuration Menu ${advsettingsmenunum}.2, item 12"
    return
  fi
  if [ "$aghloginwarned" = "1" ]; then
    aghlog "INFO" "AdGuard Home login found - DNS watch has resumed."
    aghloginwarned=0
  fi

  if [ "$aghmode" -eq 0 ] && ! dnsquerylogenabled; then
    if [ "$dnsquerylogwarned" != "1" ]; then
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: DNS watch is enabled but dnsmasq query logging is off - enable it from the Configuration Menu." >> "$logfile"
      dnsquerylogwarned=1
    fi
    return
  fi

  resolvefeedsroot
  [ -z "$feedsroot" ] && return

  local domainsfile="$feedsroot/domains.txt" qfdomfile="$feedsroot/qfeeds_domains.txt" dnspairfile="/tmp/iocmon_dns.$$"
  [ "$enableqfeeds" -eq 1 ] || qfdomfile=""
  [ -s "$domainsfile" ] || [ -s "$qfdomfile" ] || return

  local querypairs
  if [ "$aghmode" -eq 1 ]; then
    # AdGuard Home owns port 53: read its query log through the API (see aghquerypairs)
    resolvestateroot
    [ -n "$stateroot" ] && mkdir -m 755 -p "$stateroot"
    if [ "$dnslogannounced" != "adguardhome" ]; then
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: DNS watch is reading AdGuard Home's query log via its API ($(aghapiurl))." >> "$logfile"
      dnslogannounced="adguardhome"
    fi
    dnslogshort="AdGuard Home API $(aghapiurl)"
    local aghrc
    aghreadlog "$dnspairfile.agh"; aghrc=$?
    case "$aghfailover" in
      1) dnslogshort="Backup AdGuard Home ${aghurl2%/}"
         [ "${#dnslogshort}" -gt 60 ] && dnslogshort="$(printf '%.59s' "$dnslogshort")>" ;;
      2) dnslogshort="Primary and backup AdGuard Home not answering" ;;
    esac
    # 2 = first run, cursor set to now: still a completed check
    [ "$aghrc" -eq 2 ] && dnslastcheck=$(date +'%H:%M')
    [ "$aghrc" -eq 0 ] || { rm -f "$dnspairfile.agh" "$dnspairfile.agh.times"; return; }
    dnschecked="$aghqueries"
    dnslastcheck=$(date +'%H:%M')
    querypairs="$(cat "$dnspairfile.agh")"
    mv -f "$dnspairfile.agh.times" "$dnspairfile.times" 2>/dev/null
    rm -f "$dnspairfile.agh"
    [ -z "$querypairs" ] && { rm -f "$dnspairfile.times"; return; }
  else
    # dnsmasq: tail its log-queries lines
    local synclog
    resolvestateroot
    [ "$dnsforcefilelog" -eq 1 ] && [ -n "$stateroot" ] && rotatednsfilelog "$stateroot/dnsmasq_queries.log"

    resolvednslogfile
    synclog="$dnslogresolved"
    [ -f "$synclog" ] || return

    if [ "$synclog" != "$dnslogannounced" ]; then
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: DNS watch is reading $synclog ($dnslogreason)." >> "$logfile"
      dnslogannounced="$synclog"
    fi
    dnslogshort="$synclog"
    [ "${#dnslogshort}" -gt 60 ] && dnslogshort="$(printf '%.59s' "$synclog")>"

    if [ "${dnslognonecount:-0}" -ge 2 ] && [ "$dnslognonewarned" != "1" ]; then
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: DNS watch found no dnsmasq query lines in $synclog or any known dnsmasq log. If a syslog-ng/scribe filter or another tool routes dnsmasq to its own file, set that file in Advanced Settings - DNS Watch (DNS query log file)." >> "$logfile"
      dnslognonewarned=1
    fi
    [ "${dnslognonecount:-0}" -eq 0 ] && dnslognonewarned=0

    local linecount lastcount=0 newlines checkpointfile="" anchorfile="" anchor=""
    linecount="$(wc -l < "$synclog" | tr -d ' ')"

    if [ -n "$stateroot" ]; then
      mkdir -m 755 -p "$stateroot"
      checkpointfile="$stateroot/dns_checkpoint"
      anchorfile="$stateroot/dns_anchor"
      [ -f "$checkpointfile" ] && lastcount="$(cat "$checkpointfile" 2>/dev/null)"
      [ -z "$lastcount" ] && lastcount=0
      [ -f "$anchorfile" ] && anchor="$(cat "$anchorfile" 2>/dev/null)"
    elif [ -n "$dnscheckpointcache" ]; then
      lastcount="$dnscheckpointcache"
      anchor="$dnsanchorcache"
    fi

    lastcount="$(syslogresumepoint "$synclog" "$lastcount" "$anchor" "$linecount")"
    newlines=$((linecount - lastcount))

    anchor="$(tail -n 1 "$synclog")"
    [ -n "$checkpointfile" ] && echo "$linecount" > "$checkpointfile"
    [ -n "$anchorfile" ] && printf '%s\n' "$anchor" > "$anchorfile"
    dnscheckpointcache="$linecount"
    dnsanchorcache="$anchor"

    [ "$newlines" -le 0 ] && return

    dnschecked="$newlines"
    dnslastcheck=$(date +'%H:%M')

    local dnsmasqlines
    dnsmasqlines="$(tail -n "$newlines" "$synclog" | grep -Fc 'dnsmasq')"

    querypairs="$(tail -n "$newlines" "$synclog" | grep -F 'dnsmasq' | awk '
      {
        domain=""; src=""
        for (i=1; i<=NF; i++) {
          if ($i ~ /^query\[[A-Za-z]+\]$/) { domain=$(i+1) }
          if ($i=="from" && (i+1)<=NF) { src=$(i+1) }
        }
        if (domain=="" || src !~ /^[0-9A-Fa-f.:]+$/) next
        domain=tolower(domain); gsub(/[^a-z0-9._-]/, "_", domain)
        print domain"|"src
      }
    ' | sort -u)"

    if [ -z "$querypairs" ]; then
      if [ "$dnsmasqlines" -gt 0 ] && [ "$dnsquerymissingwarned" != "1" ]; then
        echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: DNS watch sees dnsmasq activity in the log but no query[...] lines. Two known causes: (1) log-queries is configured but dnsmasq hasn't picked it up yet - try 'service restart_dnsmasq'; (2) DHCP hands LAN clients a DNS server that isn't this router's own LAN IP, so queries never pass through this dnsmasq at all - check the DHCP Server DNS setting in the web UI if (1) doesn't help." >> "$logfile"
        dnsquerymissingwarned=1
      fi
      return
    fi
    dnsquerymissingwarned=0
    [ -n "$(selfqfiles)" ] && tail -n "$newlines" "$synclog" | grep -F 'dnsmasq' | dnslogtimes "$(routeraddrs)" > "$dnspairfile.times"
  fi

  dnsqueriedcount="$(echo "$querypairs" | wc -l | tr -d ' ')"

  echo "$querypairs" > "$dnspairfile"
  selfqfilter "$dnspairfile" "$dnspairfile.times"
  querypairs="$(cat "$dnspairfile")"

  if [ "$enablednstunnel" -eq 1 ]; then
    [ -n "$querypairs" ] && echo "$querypairs" | dnstunnelscan | while IFS='|' read -r kind srcip a b; do
      case "$kind" in
        LONG)
          indnsexceptionlist "$a" && continue
          raisealert "dns" "${srcip}->${a}" "dns-tunnel-heuristic" "unusually long DNS query name (${#a} chars) - possible DNS tunneling/exfiltration" "${srcip}-${a}-longname"
          ;;
        VOL)
          indnsexceptionlist "$a" && continue
          [ "$b" -ge "$dnstunnelsubthreshold" ] && raisealert "dns" "${srcip}->${a}" "dns-tunnel-heuristic" "${b} distinct subdomains queried this cycle - possible DNS tunneling/exfiltration" "${srcip}-${a}-volume"
          ;;
      esac
    done
    [ -s "$dnspairfile.self" ] && cut -d'|' -f1,2 "$dnspairfile.self" | dnstunnelscan | while IFS='|' read -r kind srcip a b; do
      case "$kind" in
        LONG) selfqinfo "tunnel:$a" "Unusually long DNS query name $a from the router ($srcip) was $(selfqwhat "$(selfqtool "$dnspairfile.self" "$srcip" "$a")") - no tunneling alert raised." ;;
        VOL)  [ "$b" -ge "$dnstunnelsubthreshold" ] && selfqinfo "tunnel:$a" "$b distinct subdomains of $a looked up by the router ($srcip) were $(selfqwhat "$(selfqtool "$dnspairfile.self" "$srcip" "$a" base)") - no tunneling alert raised." ;;
      esac
    done
  fi

  [ -s "$dnspairfile.self" ] && cut -d'|' -f1,2 "$dnspairfile.self" >> "$dnspairfile"
  set -- "$dnspairfile"
  [ -s "$domainsfile" ] && set -- "$@" "$domainsfile"
  [ -s "$qfdomfile" ] && set -- "$@" "$qfdomfile"

  awk -F'|' -v pf="$dnspairfile" -v qf="$qfdomfile" '
    function addmatch(d, sn, fn) {
      if (index(","msrc[d]",", ","sn",") == 0) msrc[d] = (msrc[d]=="" ? sn : msrc[d]","sn)
      if (index(","mfam[d]",", ","fn",") == 0) mfam[d] = (mfam[d]=="" ? fn : mfam[d]","fn)
    }
    FILENAME==pf { srcs[$1] = (srcs[$1]=="" ? $2 : srcs[$1]","$2); next }
    {
      if (FILENAME==qf) { ind=$0; srcname="qfeeds"; famname="osint-domain" } else { ind=$1; srcname=$2; famname=$3 }
      if (ind in srcs) addmatch(ind, srcname, famname)
    }
    END {
      for (d in msrc) { n = split(srcs[d], sl, ","); for (i = 1; i <= n; i++) print sl[i]"|"d"|"msrc[d]"|"mfam[d] }
    }
  ' "$@" | while IFS='|' read -r srcip matcheddomain source family; do
    selftool=""
    [ -s "$dnspairfile.self" ] && selftool="$(selfqtool "$dnspairfile.self" "$srcip" "$matcheddomain")"
    if indnsexceptionlist "$matcheddomain"; then
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: DNS query for $matcheddomain from $srcip matched the $source IoC feed but is on the DNS exception list - no alert raised." >> "$logfile"
    elif [ -n "$selftool" ]; then
      selfqinfo "feed:$matcheddomain" "DNS query for $matcheddomain from the router ($srcip) matched the $source IoC feed but was $(selfqwhat "$selftool") - no alert raised."
    else
      raisealert "dns" "${srcip}->${matcheddomain}" "$source" "$family" "$matcheddomain"
    fi
  done
  rm -f "$dnspairfile" "$dnspairfile.self" "$dnspairfile.times"
}

# -------------------------------------------------------------------------------------------------------------------------
# dnstunnelscan reads domain|src pairs on stdin and prints LONG|src|domain|base and VOL|src|base|count tunneling candidates

dnstunnelscan()
{
  awk -F'|' -v namelen="$dnstunnelnamelen" '
    {
      domain=$1; src=$2
      n=split(domain, parts, ".")
      if (n>=2) base=parts[n-1]"."parts[n]; else base=domain
      count[src"|"base]++
      if (length(domain) >= namelen) print "LONG|"src"|"domain"|"base
    }
    END {
      for (k in count) {
        split(k, kk, "|")
        print "VOL|"kk[1]"|"kk[2]"|"count[k]
      }
    }
  '
}

# -------------------------------------------------------------------------------------------------------------------------
# selfqtool $1=self file $2=src $3=name prints which add-on made that router lookup ($4=base: any name under $3), "Kairos and Astraea" if both

selfqtool()
{
  awk -F'|' -v s="$2" -v d="$3" -v b="$4" '
    $2 == s && ($1 == d || (b != "" && substr("." $1, length($1) - length(d) + 1) == "." d)) { t[$3] = 1 }
    END { if (("Kairos" in t) && ("Astraea" in t)) print "Kairos and Astraea"; else for (k in t) print k }' "$1"
}

# -------------------------------------------------------------------------------------------------------------------------
# selfqwhat $1=add-on name prints how a set-aside router lookup is described in the log

selfqwhat()
{
  case "$1" in
    Astraea) echo "Astraea's own certificate check" ;;
    Kairos) echo "Kairos's own lookup (time servers and DNS checks)" ;;
    *) echo "Kairos's and Astraea's own lookups" ;;
  esac
}

# -------------------------------------------------------------------------------------------------------------------------
# syslogaddyear rewrites a syslog "Oct  6 20:21:25" prefix on stdin as IOCMON's "Oct 06 2026 20:21:25"; other lines pass through

syslogaddyear()
{
  set -- $(date +'%Y %m %d')
  awk -v y="$1" -v m="$2" -v d="$3" '
    BEGIN { n = split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", names, " "); for (i = 1; i <= n; i++) mon[names[i]] = i }
    ($1 in mon) && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9][0-9]:/ {
      yr = y + 0
      if (mon[$1] > m + 0 || (mon[$1] == m + 0 && $2 + 0 > d + 0)) yr--
      printf "%s %02d %d %s%s\n", $1, $2, yr, $3, substr($0, index($0, $3) + length($3))
      next
    }
    { print }'
}

# -------------------------------------------------------------------------------------------------------------------------
# checkauth does a rate-based grep of new syslog lines for dropbear/httpd auth-failure patterns

checkauth()
{
  authchecked=0

  [ "$enableauthwatch" -eq 1 ] || return

  local synclog="/tmp/syslog.log"
  [ -f "$synclog" ] || return

  local sig linecount
  sig="$(wc -lc < "$synclog" | awk '{print $1":"$2}')"
  linecount="${sig%%:*}"

  authchecked=$((linecount - ${authlastlinecount:-0}))
  [ "$authchecked" -lt 0 ] && authchecked="$linecount"
  authlastlinecount="$linecount"

  if [ "$sig" = "$authsyncsig" ]; then
    authchecked=0
    return
  fi
  authsyncsig="$sig"
  authlastcheck=$(date +'%H:%M')

  resolvestateroot
  [ -n "$stateroot" ] && mkdir -m 755 -p "$stateroot"

  local nowepoch cutoff dropbearips httpdips dropbearlines httpdlines dbfirst=0 hdfirst=0
  local olddropbearlog="/jffs/addons/iocmon.d/dropbear_attempts.log" dropbearlogfile=""
  nowepoch=$(date +%s)
  cutoff=$((nowepoch - authslowwindowhrs * 3600))

  if [ -n "$stateroot" ]; then
    dropbearlogfile="$stateroot/dropbear_attempts.log"
    if [ -f "$olddropbearlog" ]; then
      if [ -s "$dropbearlogfile" ]; then
        cat "$olddropbearlog" >> "$dropbearlogfile"
      else
        mv "$olddropbearlog" "$dropbearlogfile"
      fi
      rm -f "$olddropbearlog"
      rotatelogfile "$dropbearlogfile" "$logsize"
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Migrated dropbear_attempts.log from JFFS to the state folder on the feed storage location." >> "$logfile"
    fi
    if grep -qE '^[A-Z][a-z][a-z] +[0-9]+ [0-9][0-9]:' "$dropbearlogfile" 2>/dev/null; then
      syslogaddyear < "$dropbearlogfile" > "${dropbearlogfile}.tmp" && mv -f "${dropbearlogfile}.tmp" "$dropbearlogfile"
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Added the year to existing dropbear_attempts.log dates." >> "$logfile"
    fi
  fi

  [ -f "$dropbearseenfile" ] || dbfirst=1
  [ -f "$httpdseenfile" ] || hdfirst=1

  dropbearlines="$(grep -F 'dropbear' "$synclog" | grep -E 'Bad password attempt|Login attempt for nonexistent user' | authnewlines "$dropbearseenfile")"
  httpdlines="$(grep -E ' (HTTPD|httpd)(\[[0-9]+\])?: ' "$synclog" | grep -iE '\[LOGIN\]\[[a-z]+\]\[[a-z]+\] failed \(|login.?fail|invalid.?password|authentication.?fail' | authnewlines "$httpdseenfile")"

  if [ "$dbfirst" -eq 1 ]; then
    dropbearlines=""
    if [ -n "$dropbearlogfile" ] && [ -s "$dropbearlogfile" ]; then
      awk '!seenline[$0]++' "$dropbearlogfile" > "/tmp/iocmon_dbdedupe.$$" && mv "/tmp/iocmon_dbdedupe.$$" "$dropbearlogfile"
    fi
    [ -n "$stateroot" ] && : > "$stateroot/auth_slow_dropbear.db"
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Dropbear attempt ledger initialized - de-duplicated the existing dropbear log and reset the sustained-attempt counter." >> "$logfile"
  fi
  if [ "$hdfirst" -eq 1 ]; then
    httpdlines=""
    [ -n "$stateroot" ] && : > "$stateroot/auth_slow_httpd.db"
  fi

  if [ -n "$dropbearlines" ] && [ -n "$dropbearlogfile" ]; then
    echo "$dropbearlines" | syslogaddyear >> "$dropbearlogfile"
    rotatelogfile "$dropbearlogfile" "$logsize"
  fi
  dropbearips="$(echo "$dropbearlines" | grep -oE 'from [0-9]{1,3}(\.[0-9]{1,3}){3}' | awk '{print $2}')"

  httpdips="$(echo "$httpdlines" | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')"

  if [ -n "$dropbearips" ]; then
    [ -n "$stateroot" ] && echo "$dropbearips" | awk -v now="$nowepoch" '{print now"|"$0}' >> "$stateroot/auth_slow_dropbear.db"
    echo "$dropbearips" | sort | uniq -c | while read -r attemptcount sourceip; do
      [ "$attemptcount" -ge "$authfailthreshold" ] && raisealert "auth" "$sourceip" "dropbear" "$attemptcount attempts this cycle (burst)"
    done
  fi

  if [ -n "$httpdips" ]; then
    [ -n "$stateroot" ] && echo "$httpdips" | awk -v now="$nowepoch" '{print now"|"$0}' >> "$stateroot/auth_slow_httpd.db"
    echo "$httpdips" | sort | uniq -c | while read -r attemptcount sourceip; do
      [ "$attemptcount" -ge "$authfailthreshold" ] && raisealert "auth" "$sourceip" "httpd" "$attemptcount attempts this cycle (burst)"
    done
  fi

  [ -z "$stateroot" ] && return

  local slowfile
  for slowfile in "$stateroot/auth_slow_dropbear.db" "$stateroot/auth_slow_httpd.db"; do
    [ -f "$slowfile" ] || continue
    awk -F'|' -v cutoff="$cutoff" '$1+0 >= cutoff' "$slowfile" > "${slowfile}.tmp" && mv "${slowfile}.tmp" "$slowfile"
  done

  if [ -s "$stateroot/auth_slow_dropbear.db" ]; then
    awk -F'|' '{c[$2]++} END{for (ip in c) print c[ip]"|"ip}' "$stateroot/auth_slow_dropbear.db" | \
      while IFS='|' read -r slowcount sourceip; do
        [ -n "$sourceip" ] && [ "$slowcount" -ge "$authslowthreshold" ] && raisealert "auth" "$sourceip" "dropbear" "$slowcount attempts over the last ${authslowwindowhrs}h (sustained low-rate)" "${sourceip}-slow"
      done
  fi

  if [ -s "$stateroot/auth_slow_httpd.db" ]; then
    awk -F'|' '{c[$2]++} END{for (ip in c) print c[ip]"|"ip}' "$stateroot/auth_slow_httpd.db" | \
      while IFS='|' read -r slowcount sourceip; do
        [ -n "$sourceip" ] && [ "$slowcount" -ge "$authslowthreshold" ] && raisealert "auth" "$sourceip" "httpd" "$slowcount attempts over the last ${authslowwindowhrs}h (sustained low-rate)" "${sourceip}-slow"
      done
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# checknvram diffs a hardcoded watchlist ($nvramwatchvars) of security-relevant NVRAM variables every tick

checknvram()
{
  [ "$enablenvramwatch" -eq 1 ] || return

  resolvestateroot
  [ -z "$stateroot" ] && return
  mkdir -m 755 -p "$stateroot"

  local baseline="$stateroot/nvram_baseline.db" newbaseline="$stateroot/nvram_baseline.db.new"
  local firstrun=0 var newval oldval recorded change
  nvramlastcheck=$(date +'%H:%M')
  [ -s "$baseline" ] || firstrun=1
  recorded="$(awk -F'=' '$1=="__recorded"{sub(/^[^=]*=/,""); print; exit}' "$baseline" 2>/dev/null)"

  echo "__recorded=$(date +'%b %d %Y %X')" > "$newbaseline"
  for var in $nvramwatchvars; do
    if ! nvramget "$var"; then
      grep "^${var}=" "$baseline" >> "$newbaseline" 2>/dev/null
      continue
    fi
    newval="$(printf '%s\n' "$nvramval" | tr '\n' ' ')"
    newval="${newval% }"
    echo "${var}=${newval}" >> "$newbaseline"

    if [ "$firstrun" -eq 0 ] && grep -q "^${var}=" "$baseline" 2>/dev/null; then
      oldval="$(awk -F'=' -v v="$var" '$1==v{sub(/^[^=]*=/,""); print; exit}' "$baseline" 2>/dev/null)"
      if [ "$newval" != "$oldval" ]; then
        change="changed from '${oldval:-<empty>}' to '${newval:-<empty>}'${recorded:+ (last recorded $recorded)}"
        aghlog "INFO" "NVRAM $var $change."
        raisealert "nvram" "$var" "nvram-change" "$change"
      fi
    fi
  done

  mv "$newbaseline" "$baseline"
}

# -------------------------------------------------------------------------------------------------------------------------
# quarantinefile is the opt-in (enablequarantine, default off) response to a confirmed hash match

quarantinefile()
{
  local path="$1"
  [ "$enablequarantine" -eq 1 ] || return
  [ -f "$path" ] || return

  chmod -x "$path" 2>/dev/null
  mv "$path" "${path}.iocmon-quarantine" 2>/dev/null
  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: Quarantined $path -> ${path}.iocmon-quarantine (execute bit stripped, not deleted)." >> "$logfile"
}

# -------------------------------------------------------------------------------------------------------------------------
# filecontenthash computes one cheap content hash for $1, whichever of md5/sha1/sha256 is first available

filecontenthash()
{
  local path="$1"
  if which md5sum >/dev/null 2>&1; then md5sum "$path" 2>/dev/null | awk '{print $1}'
  elif which sha1sum >/dev/null 2>&1; then sha1sum "$path" 2>/dev/null | awk '{print $1}'
  elif which sha256sum >/dev/null 2>&1; then sha256sum "$path" 2>/dev/null | awk '{print $1}'
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# fscontenthashchanged updates $1's stored content-hash baseline and reports whether it genuinely changed since last time

fscontenthashchanged()
{
  local path="$1" hashdb newhash oldhash tmpfile
  [ -z "$stateroot" ] && return 0
  hashdb="$stateroot/fs_content_hash.db"
  newhash="$(filecontenthash "$path")"
  [ -z "$newhash" ] && return 0
  oldhash="$(awk -F'\t' -v p="$path" '$1==p{print $2}' "$hashdb" 2>/dev/null)"
  tmpfile="${hashdb}.tmp"
  awk -F'\t' -v p="$path" '$1!=p' "$hashdb" 2>/dev/null > "$tmpfile"
  printf '%s\t%s\n' "$path" "$newhash" >> "$tmpfile"
  mv "$tmpfile" "$hashdb"
  [ -z "$oldhash" ] && return 1
  [ "$oldhash" != "$newhash" ]
}

# -------------------------------------------------------------------------------------------------------------------------
# hashmatchcheck computes whichever of md5/sha1/sha256 are available for one file and checks them against feeds/hashes.txt.

hashmatchcheck()
{
  local path="$1" hashesfile="$2" md5="" sha1="" sha256="" match hashchecklogfile hashlogprefix

  which md5sum >/dev/null 2>&1 && md5="$(md5sum "$path" 2>/dev/null | awk '{print $1}')"
  which sha1sum >/dev/null 2>&1 && sha1="$(sha1sum "$path" 2>/dev/null | awk '{print $1}')"
  which sha256sum >/dev/null 2>&1 && sha256="$(sha256sum "$path" 2>/dev/null | awk '{print $1}')"

  match="$(printf '%s\n%s\n%s\n' "$md5" "$sha1" "$sha256" | grep -v '^$' | awk -F'|' '
    FNR==NR { h[$1] = $2"|"$3; next }
    { if ($0 in h) print $0"|"h[$0] }
  ' "$hashesfile" -)"

  if [ -n "$stateroot" ]; then
    hashchecklogfile="$stateroot/hash_check.log"
    hashlogprefix="$(date +'%b %d %Y %X') | $path | md5=${md5:-n/a} sha1=${sha1:-n/a} sha256=${sha256:-n/a}"
    if [ -n "$match" ]; then
      echo "$match" | while IFS='|' read -r matchedhash source family; do
        echo "${hashlogprefix} | MATCH: hash=${matchedhash} source=${source} family=${family}" >> "$hashchecklogfile"
      done
    else
      echo "${hashlogprefix} | no match" >> "$hashchecklogfile"
    fi
    rotatelogfile "$hashchecklogfile" "$logsize"
  fi

  [ -z "$match" ] && return

  echo "$match" | while IFS='|' read -r matchedhash source family; do
    raisealert "fsintegrity" "$path" "$source" "hash match $matchedhash ($family)"
    quarantinefile "$path"
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# isstartupscript succeeds if file name $1 is one the firmware runs by itself from /jffs/scripts

isstartupscript()
{
  case " $fsstartupscripts " in
    *" $1 "*) return 0 ;;
  esac
  case "$1" in
    *.postconf) return 0 ;;
  esac
  return 1
}

# -------------------------------------------------------------------------------------------------------------------------
# processfschange applies every no-feed heuristic 

processfschange()
{
  local changetype="$1" path="$2" size="$3" isexec="$4" hashesfile="$5" base dir

  case "$path" in
    *.iocmon-quarantine) return ;;
  esac

  case "$path" in
    */.ssh/*)
      if [ "$changetype" != "MOD" ] || [ "$fsmodalertmode" != "hash" ] || fscontenthashchanged "$path"; then
        raisealert "fsintegrity" "$path" "ssh-directory-change" "$changetype - review immediately, not hash-matched"
      fi
      ;;
  esac

  base="${path##*/}"
  dir="${path%/*}"
  if [ "$dir" = "/jffs/scripts" ] && isstartupscript "$base"; then
    if [ "$changetype" = "MOD" ] && [ "$fsmodalertmode" = "hash" ]; then
      fscontenthashchanged "$path" && raisealert "fsintegrity" "$path" "startup-script-edit" "HASH - review file content changes"
    else
      raisealert "fsintegrity" "$path" "startup-script-edit" "$changetype - review regardless of hash match"
    fi
  fi

  case "$base" in
    *.conf.add)
      if [ "$dir" = "/jffs/configs" ]; then
        if [ "$changetype" = "MOD" ] && [ "$fsmodalertmode" = "hash" ]; then
          fscontenthashchanged "$path" && raisealert "fsintegrity" "$path" "router-config-override" "HASH - review file content changes (e.g. dnsmasq DNS/upstream-resolver tampering)"
        else
          raisealert "fsintegrity" "$path" "router-config-override" "$changetype - review regardless of hash match (e.g. dnsmasq DNS/upstream-resolver tampering)"
        fi
      fi
      ;;
  esac

  if [ "$changetype" = "NEW" ] && [ "$isexec" = "1" ]; then
    raisealert "fsintegrity" "$path" "new-executable" "new file appeared with execute bit set"
  fi

  if [ -n "$hashesfile" ] && [ -s "$hashesfile" ] && [ -f "$path" ] && [ "$size" -le "$fsmaxhashsize" ]; then
    hashmatchcheck "$path" "$hashesfile"
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# processfsdeletion is processfschange's counterpart for a path that VANISHED between two baseline scans.

processfsdeletion()
{
  local path="$1" base dir

  [ -f "${path}.iocmon-quarantine" ] && return

  base="${path##*/}"
  dir="${path%/*}"

  case "$path" in
    */.ssh/*)
      raisealert "fsintegrity" "$path" "ssh-directory-change" "file deleted - review immediately"
      return
      ;;
  esac

  [ "$dir" = "/jffs/scripts" ] && isstartupscript "$base" && raisealert "fsintegrity" "$path" "startup-script-deleted" "file deleted - review regardless of cause"

  case "$base" in
    *.conf.add)
      [ "$dir" = "/jffs/configs" ] && raisealert "fsintegrity" "$path" "router-config-deleted" "file deleted - review regardless of cause (e.g. a config override being removed to re-enable a disabled protection)"
      ;;
  esac
}

# -------------------------------------------------------------------------------------------------------------------------
# fspathexcluded is the single shared exclusion rule set (self-paths, quarantine suffix, fswatchexclude, fsexcludeext, fsexcludefiles) for every filesystem-integrity path.

fspathexcluded()
{
  local path="$1" ex extpattern

  case "$path" in
    "$iocmonroot"|"$iocmonroot"/*) return 0 ;;
    "$addonsdir"|"$addonsdir"/*) return 0 ;;
    "$CUSTOM_EMAIL_LIBDir"|"$CUSTOM_EMAIL_LIBDir"/*) return 0 ;;
    *.iocmon-quarantine) return 0 ;;
  esac

  for ex in $fswatchexclude; do
    case "$path" in
      */"$ex"/*) return 0 ;;
    esac
  done

  for ex in $fsexcludefiles; do
    case "$path" in
      "$ex") return 0 ;;
    esac
  done

  for ex in $fsexcludeext; do
    case "$ex" in
      .*) extpattern="$ex" ;;
      *) extpattern=".$ex" ;;
    esac
    case "$path" in
      *"$extpattern") return 0 ;;
    esac
  done

  return 1
}

# -------------------------------------------------------------------------------------------------------------------------
# realdirpath resolves $1 to its canonical, symlink-free absolute form.

realdirpath()
{
  local resolved
  resolved="$(cd -P "$1" 2>/dev/null && pwd -P)"
  if [ -n "$resolved" ]; then echo "$resolved"; else echo "$1"; fi
}

# -------------------------------------------------------------------------------------------------------------------------
# fswatchdiroverlap checks $1 (a candidate new $fswatchdirs entry) against every already-configured entry

fswatchdiroverlap()
{
  local candidate="$1" resolvedcandidate existing resolvedexisting

  resolvedcandidate="$(realdirpath "$candidate")"
  [ -z "$resolvedcandidate" ] && return 1

  for existing in $fswatchdirs; do
    [ -d "$existing" ] || continue
    resolvedexisting="$(realdirpath "$existing")"
    [ -z "$resolvedexisting" ] && continue

    if [ "$resolvedcandidate" = "$resolvedexisting" ]; then
      echo "This resolves to the exact same directory as the already-configured entry \"$existing\" ($resolvedexisting)."
      return 0
    fi
    case "$resolvedcandidate" in
      "$resolvedexisting"/*)
        echo "This is already covered by the existing entry \"$existing\" (resolves to $resolvedexisting)."
        return 0
        ;;
    esac
    case "$resolvedexisting" in
      "$resolvedcandidate"/*)
        echo "This would already cover the existing entry \"$existing\" (resolves to $resolvedexisting) - consider removing that one instead."
        return 0
        ;;
    esac
  done

  return 1
}

# -------------------------------------------------------------------------------------------------------------------------
# iswritablebit checks $1's OWN mode bits for a write permission (owner, group, or other)

iswritablebit()
{
  local perm
  perm="$(ls -ld "$1" 2>/dev/null | cut -c1-10)"
  case "${perm#?}" in
    *w*) return 0 ;;
    *) return 1 ;;
  esac
}

# -------------------------------------------------------------------------------------------------------------------------
# filesizeof echoes $1's byte size via ls -l - measured far cheaper per call than wc -c on real hardware.

filesizeof()
{
  local sz
  sz="$(ls -l "$1" 2>/dev/null | awk '{print $5}')"
  [ -z "$sz" ] && sz=0
  echo "$sz"
}

# -------------------------------------------------------------------------------------------------------------------------
# buildsizebaseline writes path<TAB>size for every watched file into $1 - one find call per directory when findsupportsprintf, else a per-file ls fallback.

buildsizebaseline()
{
  local outfile="$1" oldmanifest="$2" label="$3" counttotal="$4"
  local d realdir path sz scancounter=0 tab
  tab="$(printf '\t')"

  : > "$outfile"

  if [ "$findsupportsprintf" -eq 1 ]; then
    for d in $fswatchdirs; do
      [ -d "$d" ] || continue
      realdir="$(realdirpath "$d")"
      "$findbin" "$realdir" -type f -printf '%p\t%s\n' 2>/dev/null | while IFS="$tab" read -r path sz; do
        fspathexcluded "$path" || printf '%s\t%s\n' "$path" "$sz"
      done >> "$outfile"
    done
    sort -u "$outfile" -o "$outfile"
  else
    while IFS= read -r path; do
      [ -z "$path" ] && continue
      scancounter=$((scancounter+1))
      [ $((scancounter % 25)) -eq 0 ] && fsscanprogress "$label" "$scancounter" "$counttotal"
      sz="$(filesizeof "$path")"
      printf '%s\t%s\n' "$path" "$sz" >> "$outfile"
    done < "$oldmanifest"
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# checkfsintegrity - poll-based manifest diff against fs_baseline.db; both find calls use only -type f/-newer, with all exclusion applied via fspathexcluded() post-filtering rather than find-native predicates.

checkfsintegrity()
{
  local hashesfile="" d realdir
  local newmanifest="$stateroot/fs_baseline.db.new" oldmanifest="$stateroot/fs_baseline.db"
  local marker="$stateroot/fs_scan_marker" newmarker="$stateroot/fs_scan_marker.new"
  local newpathsfile="$stateroot/fs_newpaths.tmp" modpathsfile="$stateroot/fs_modpaths.tmp"
  local delpathsfile="$stateroot/fs_delpaths.tmp"
  local permbaseline="$stateroot/fs_perm_baseline.db" newpermbaseline="$stateroot/fs_perm_baseline.db.new"
  local permchangesfile="$stateroot/fs_permchanges.tmp"
  local sizebaseline="$stateroot/fs_size_baseline.db" newsizebaseline="$stateroot/fs_size_baseline.db.new"
  local sizechangesfile="$stateroot/fs_sizechanges.tmp"
  local lastnewfile="$stateroot/fs_last_new.txt" lastmodfile="$stateroot/fs_last_modified.txt"
  local lastdelfile="$stateroot/fs_last_deleted.txt" lastpermfile="$stateroot/fs_last_permchanged.txt"
  local scansummary="$stateroot/fs_scan_summary.txt" scanerrors="$stateroot/fs_scan_errors.txt"
  local dircount=0 watcheddirs="" dirfilecount path filesize isexec pex pwr sz permdesc permtab scandate
  local totaldirs scancounter sizetotal hashtotal

  fsdircount=0; fsscannedcount=0; fsnewcount=0; fsmodcount=0; fsdelcount=0; fspermcount=0

  resolvefeedsroot
  [ -n "$feedsroot" ] && hashesfile="$feedsroot/hashes.txt"

  : > "$newmanifest"
  : > "$scanerrors"
  touch "$newmarker"

  totaldirs="$(echo "$fswatchdirs" | wc -w | tr -d ' ')"
  scancounter=0
  for d in $fswatchdirs; do
    scancounter=$((scancounter+1))
    if [ ! -d "$d" ]; then
      watcheddirs="${watcheddirs}${d}: not found\n"
      continue
    fi
    realdir="$(realdirpath "$d")"
    printf '\33[2K\r  %b*%b Scanning directory %s/%s: %s...' "$CGreen" "$CClear" "$scancounter" "$totaldirs" "$realdir"
    dirfilecount="$("$findbin" "$realdir" -type f -print 2>>"$scanerrors" | while IFS= read -r p; do fspathexcluded "$p" || printf '%s\n' "$p"; done | tee -a "$newmanifest" | wc -l | tr -d ' ')"
    watcheddirs="${watcheddirs}${realdir}: ${dirfilecount} files\n"
    dircount=$((dircount+1))
  done

  sort -u "$newmanifest" -o "$newmanifest"
  fsdircount=$dircount

  {
    printf 'Last scan: %s\n' "$(date +'%b %d %Y %X')"
    printf 'Directories watched (%d of %d configured):\n' "$dircount" "$(echo "$fswatchdirs" | wc -w | tr -d ' ')"
    printf "$watcheddirs"
  } > "$scansummary"

  if [ -s "$scanerrors" ]; then
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - ERROR: Filesystem-integrity scan hit $(wc -l < "$scanerrors" | tr -d ' ') find error(s) - see $scanerrors on the router. First: $(head -n1 "$scanerrors")" >> "$logfile"
  fi

  if [ -z "$dircount" ] || [ "$dircount" -eq 0 ]; then
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: Filesystem-integrity scan found none of the configured fswatchdirs on disk - check the path list in Advanced Settings." >> "$logfile"
    rm -f "$newmarker"
    touch "$lastnewfile" "$lastmodfile" "$lastdelfile" "$lastpermfile"
    return
  fi

  if [ ! -s "$oldmanifest" ]; then
    mv "$newmanifest" "$oldmanifest"
    mv "$newmarker" "$marker"
    fsscannedcount="$(wc -l < "$oldmanifest" | tr -d ' ')"
    buildsizebaseline "$newsizebaseline" "$oldmanifest" "Building initial size baseline" "$fsscannedcount"
    mv "$newsizebaseline" "$sizebaseline"
    if [ "$enablepermwatch" -eq 1 ]; then
      scancounter=0
      : > "$newpermbaseline"
      while IFS= read -r path; do
        [ -z "$path" ] && continue
        scancounter=$((scancounter+1))
        [ $((scancounter % 25)) -eq 0 ] && fsscanprogress "Building initial permission baseline" "$scancounter" "$fsscannedcount"
        if [ -x "$path" ]; then pex=1; else pex=0; fi
        if iswritablebit "$path"; then pwr=1; else pwr=0; fi
        printf '%s\t%s\t%s\n' "$path" "$pex" "$pwr" >> "$newpermbaseline"
      done < "$oldmanifest"
      mv "$newpermbaseline" "$permbaseline"
    fi
    touch "$lastnewfile" "$lastmodfile" "$lastdelfile" "$lastpermfile"
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Filesystem-integrity baseline established ($fsscannedcount files across $dircount directories)." >> "$logfile"
    return
  fi

  awk 'FNR==NR{old[$0]=1; next} !($0 in old)' "$oldmanifest" "$newmanifest" > "$newpathsfile"

  if [ "$enablefsdeletionwatch" -eq 1 ]; then
    if [ -s "$newmanifest" ]; then
      awk 'FNR==NR{new[$0]=1; next} !($0 in new)' "$newmanifest" "$oldmanifest" > "$delpathsfile"
    else
      cp "$oldmanifest" "$delpathsfile"
    fi
  else
    : > "$delpathsfile"
  fi

  : > "$modpathsfile"
  if [ -f "$marker" ]; then
    scancounter=0
    for d in $fswatchdirs; do
      scancounter=$((scancounter+1))
      [ -d "$d" ] || continue
      realdir="$(realdirpath "$d")"
      printf '\33[2K\r  %b*%b Checking for modified files %s/%s: %s...' "$CGreen" "$CClear" "$scancounter" "$totaldirs" "$realdir"
      "$findbin" "$realdir" -type f -newer "$marker" -print 2>/dev/null | while IFS= read -r p; do fspathexcluded "$p" || printf '%s\n' "$p"; done >> "$modpathsfile"
    done
  fi
  sort -u "$modpathsfile" -o "$modpathsfile"
  awk 'FNR==NR{new[$0]=1; next} !($0 in new)' "$newpathsfile" "$modpathsfile" > "${modpathsfile}.tmp"
  mv "${modpathsfile}.tmp" "$modpathsfile"

  mv "$newmanifest" "$oldmanifest"
  mv "$newmarker" "$marker"

  sizetotal="$(wc -l < "$oldmanifest" | tr -d ' ')"
  buildsizebaseline "$newsizebaseline" "$oldmanifest" "Computing size baseline" "$sizetotal"

  : > "$sizechangesfile"
  if [ -s "$sizebaseline" ]; then
    awk -F'\t' '
      FNR==NR { osize[$1]=$2; next }
      ($1 in osize) && ($2 != osize[$1]) { print $1 }
    ' "$sizebaseline" "$newsizebaseline" > "$sizechangesfile"
  fi
  mv "$newsizebaseline" "$sizebaseline"

  if [ -s "$sizechangesfile" ]; then
    cat "$modpathsfile" "$sizechangesfile" | sort -u > "${modpathsfile}.tmp"
    mv "${modpathsfile}.tmp" "$modpathsfile"
  fi

  fsscannedcount="$(wc -l < "$oldmanifest" | tr -d ' ')"
  fsnewcount="$(wc -l < "$newpathsfile" | tr -d ' ')"
  fsmodcount="$(wc -l < "$modpathsfile" | tr -d ' ')"
  fsdelcount="$(wc -l < "$delpathsfile" | tr -d ' ')"

  : > "$permchangesfile"
  if [ "$enablepermwatch" -eq 1 ]; then
    scancounter=0
    : > "$newpermbaseline"
    while IFS= read -r path; do
      [ -z "$path" ] && continue
      scancounter=$((scancounter+1))
      [ $((scancounter % 25)) -eq 0 ] && fsscanprogress "Computing permission baseline" "$scancounter" "$sizetotal"
      if [ -x "$path" ]; then pex=1; else pex=0; fi
      if iswritablebit "$path"; then pwr=1; else pwr=0; fi
      printf '%s\t%s\t%s\n' "$path" "$pex" "$pwr" >> "$newpermbaseline"
    done < "$oldmanifest"

    if [ -s "$permbaseline" ]; then
      awk -F'\t' '
        FNR==NR { oex[$1]=$2; owr[$1]=$3; next }
        ($1 in oex) {
          exadd = ($2=="1" && oex[$1]=="0") ? 1 : 0
          wradd = ($3=="1" && owr[$1]=="0") ? 1 : 0
          if (exadd || wradd) print $1"\t"exadd"\t"wradd
        }
      ' "$permbaseline" "$newpermbaseline" > "$permchangesfile"
    fi

    mv "$newpermbaseline" "$permbaseline"
  fi
  fspermcount="$(wc -l < "$permchangesfile" | tr -d ' ')"

  scandate="$(date +'%b %d %Y %X')"
  [ -s "$newpathsfile" ] && sed "s#^#${scandate} #" "$newpathsfile" >> "$lastnewfile"
  [ -s "$modpathsfile" ] && sed "s#^#${scandate} #" "$modpathsfile" >> "$lastmodfile"
  [ -s "$delpathsfile" ] && sed "s#^#${scandate} #" "$delpathsfile" >> "$lastdelfile"
  [ -s "$permchangesfile" ] && cut -f1 "$permchangesfile" | sed "s#^#${scandate} #" >> "$lastpermfile"
  rotatelogfile "$lastnewfile" "$logsize"
  rotatelogfile "$lastmodfile" "$logsize"
  rotatelogfile "$lastdelfile" "$logsize"
  rotatelogfile "$lastpermfile" "$logsize"

  {
    printf '[%s1%s] New files list: %s (%s new entries)\n' "$CGreen" "$CClear" "$lastnewfile" "$fsnewcount"
    printf '[%s2%s] Modified files list: %s (%s new entries)\n' "$CGreen" "$CClear" "$lastmodfile" "$fsmodcount"
    printf '[%s3%s] Deleted files list: %s (%s new entries)\n' "$CGreen" "$CClear" "$lastdelfile" "$fsdelcount"
    printf '[%s4%s] Permission-changed files list: %s (%s new entries)\n' "$CGreen" "$CClear" "$lastpermfile" "$fspermcount"
  } >> "$scansummary"

  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Filesystem-integrity scan complete: $fsscannedcount files scanned across $dircount directories; $fsnewcount new and $fsmodcount modified file(s) checked against known-malware hashes; $fsdelcount deletion(s) detected in critical watched paths; $fspermcount permission-only change(s) detected." >> "$logfile"

  if [ ! -s "$newpathsfile" ] && [ ! -s "$modpathsfile" ] && [ ! -s "$delpathsfile" ] && [ ! -s "$permchangesfile" ]; then
    rm -f "$newpathsfile" "$modpathsfile" "$delpathsfile" "$permchangesfile" "$sizechangesfile"
    return
  fi

  scancounter=0
  hashtotal=$((fsnewcount + fsmodcount))
  { sed 's/^/NEW:/' "$newpathsfile"; sed 's/^/MOD:/' "$modpathsfile"; } | while IFS=: read -r changetype path; do
    [ -f "$path" ] || continue
    scancounter=$((scancounter+1))
    [ $((scancounter % 5)) -eq 0 ] && fsscanprogress "Hashing changed files" "$scancounter" "$hashtotal"
    filesize="$(filesizeof "$path")"
    if [ -x "$path" ]; then isexec=1; else isexec=0; fi
    processfschange "$changetype" "$path" "$filesize" "$isexec" "$hashesfile"
  done

  if [ -s "$delpathsfile" ]; then
    while IFS= read -r path; do
      [ -z "$path" ] && continue
      processfsdeletion "$path"
    done < "$delpathsfile"
  fi

  if [ -s "$permchangesfile" ]; then
    permtab="$(printf '\t')"
    while IFS="$permtab" read -r path pex pwr; do
      [ -z "$path" ] && continue
      grep -qxF "$path" "$modpathsfile" 2>/dev/null && continue
      permdesc=""
      [ "$pex" = "1" ] && permdesc="execute bit added"
      if [ "$pwr" = "1" ]; then
        if [ -n "$permdesc" ]; then permdesc="$permdesc, write bit added"; else permdesc="write bit added"; fi
      fi
      raisealert "fsintegrity" "$path" "permission-escalation" "$permdesc - file content/mtime unchanged"
    done < "$permchangesfile"
  fi

  rm -f "$newpathsfile" "$modpathsfile" "$delpathsfile" "$permchangesfile" "$sizechangesfile"
}

# -------------------------------------------------------------------------------------------------------------------------
# cronmatchkey strips a cron line's leading 5 schedule fields (minute hour day-of-month month day-of-week)

cronmatchkey()
{
  printf '%s\n' "$1" | sed -E 's/^([^[:space:]]+[[:space:]]+){5}//'
}

# -------------------------------------------------------------------------------------------------------------------------
# incronexceptionlist checks against the established list of cron exceptions

incronexceptionlist()
{
  local entry="$1" candidatekey ex exkey
  [ -z "$cronexceptions" ] && return 1

  candidatekey="$(cronmatchkey "$entry")"
  [ -z "$candidatekey" ] && return 1

  while IFS= read -r ex; do
    [ -z "$ex" ] && continue
    exkey="$(cronmatchkey "$ex")"
    [ "$candidatekey" = "$exkey" ] && return 0
  done <<EOF
$cronexceptions
EOF

  return 1
}

# -------------------------------------------------------------------------------------------------------------------------
# checkcronbaseline alerts on any cru entry that appeared since the last check

checkcronbaseline()
{
  [ "$enablecrondiff" -eq 1 ] || return

  local newcron="$stateroot/cron_baseline.db.new" oldcron="$stateroot/cron_baseline.db" newentries

  crul || return
  printf '%s\n' "$cruout" | sed '/^$/d' | sort > "$newcron"

  if [ ! -s "$oldcron" ]; then
    mv "$newcron" "$oldcron"
    return
  fi

  newentries="$(awk 'FNR==NR{old[$0]=1; next} !($0 in old)' "$oldcron" "$newcron")"
  mv "$newcron" "$oldcron"

  [ -z "$newentries" ] && return

  echo "$newentries" | while IFS= read -r entry; do
    [ -z "$entry" ] && continue
    if incronexceptionlist "$entry"; then
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: New cru entry matches the cron exceptions list, not alerting: $entry" >> "$logfile"
      continue
    fi
    raisealert "cron" "$entry" "cru" "unexpected new cron entry"
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# checkentwarecron is checkcronbaseline's counterpart for Entware's own cron daemon (the "cron" opkg package)

checkentwarecron()
{
  [ "$enablecrondiff" -eq 1 ] || return

  local newtab="$stateroot/entware_cron_baseline.db.new" oldtab="$stateroot/entware_cron_baseline.db" newentries
  local srcfiles="" f

  [ -f /opt/etc/crontab ] && srcfiles="/opt/etc/crontab"
  for f in /opt/var/spool/cron/crontabs/*; do
    [ -f "$f" ] && srcfiles="$srcfiles $f"
  done
  [ -z "$srcfiles" ] && return

  cat $srcfiles 2>/dev/null | grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$' | sort > "$newtab"

  if [ ! -s "$oldtab" ]; then
    mv "$newtab" "$oldtab"
    return
  fi

  newentries="$(awk 'FNR==NR{old[$0]=1; next} !($0 in old)' "$oldtab" "$newtab")"
  mv "$newtab" "$oldtab"

  [ -z "$newentries" ] && return

  echo "$newentries" | while IFS= read -r entry; do
    [ -z "$entry" ] && continue
    if incronexceptionlist "$entry"; then
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: New Entware cron entry matches the cron exceptions list, not alerting: $entry" >> "$logfile"
      continue
    fi
    raisealert "cron" "$entry" "entware-cron" "unexpected new Entware cron entry"
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# checkfirewallrules alerts on a new port-forward, gaming/"Open NAT" port-forward, or UPnP-created NAT rule

checkfirewallrules()
{
  [ "$enablefwrulediff" -eq 1 ] || return
  which iptables-save >/dev/null 2>&1 || return

  local newtab="$stateroot/fw_rules_baseline.db.new" oldtab="$stateroot/fw_rules_baseline.db" newentries

  iptables-save -t nat 2>/dev/null | grep -E '^-A (VSERVER|GAME_VSERVER|VUPNP) ' | sort > "$newtab"

  if [ ! -s "$oldtab" ]; then
    mv "$newtab" "$oldtab"
    return
  fi

  newentries="$(awk 'FNR==NR{old[$0]=1; next} !($0 in old)' "$oldtab" "$newtab")"
  mv "$newtab" "$oldtab"

  [ -z "$newentries" ] && return

  echo "$newentries" | while IFS= read -r entry; do
    [ -z "$entry" ] && continue
    raisealert "firewall" "$entry" "nat-rule" "unexpected new port-forward/UPnP NAT rule - review for unauthorized WAN exposure"
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# checketccritical always-alerts on any change to $etccriticalpaths (accounts, pam.d, certs, VPN secrets), ignoring fsmodalertmode

checketccritical()
{
  [ "$enableetccritical" -eq 1 ] || return
  [ -n "$stateroot" ] || return

  local hashdb="$stateroot/etc_critical_hash.db" curlist path h entry oldhash

  curlist="$(mktemp 2>/dev/null || echo "/tmp/iocmon_etccritical_cur.$$")"
  : > "$curlist"
  for entry in $etccriticalpaths; do
    if [ -d "$entry" ]; then
      find "$entry" -type f 2>/dev/null >> "$curlist"
    elif [ -f "$entry" ]; then
      echo "$entry" >> "$curlist"
    fi
  done
  sort -u "$curlist" -o "$curlist"

  if [ ! -f "$hashdb" ]; then
    : > "$hashdb"
    while IFS= read -r path; do
      [ -z "$path" ] && continue
      h="$(filecontenthash "$path")"
      [ -n "$h" ] && printf '%s\t%s\n' "$path" "$h" >> "$hashdb"
    done < "$curlist"
    rm -f "$curlist"
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Critical /etc baseline established ($(wc -l < "$hashdb" | tr -d ' ') file(s))." >> "$logfile"
    return
  fi

  awk -F'\t' 'FNR==NR{old[$1]=1; next} !($1 in old)' "$hashdb" "$curlist" | while IFS= read -r path; do
    [ -z "$path" ] && continue
    raisealert "fsintegrity" "$path" "etc-critical-new" "a new file appeared under a watched critical /etc path - review immediately"
  done

  awk -F'\t' '{print $1}' "$hashdb" | while IFS= read -r path; do
    [ -z "$path" ] && continue
    grep -qxF "$path" "$curlist" || raisealert "fsintegrity" "$path" "etc-critical-deleted" "a critical /etc file was deleted - review immediately"
  done

  while IFS= read -r path; do
    [ -z "$path" ] && continue
    oldhash="$(awk -F'\t' -v p="$path" '$1==p{print $2}' "$hashdb")"
    [ -z "$oldhash" ] && continue
    h="$(filecontenthash "$path")"
    [ -n "$h" ] && [ "$h" != "$oldhash" ] && raisealert "fsintegrity" "$path" "etc-critical-modified" "critical /etc file content changed - review immediately"
  done < "$curlist"

  : > "$hashdb"
  while IFS= read -r path; do
    [ -z "$path" ] && continue
    h="$(filecontenthash "$path")"
    [ -n "$h" ] && printf '%s\t%s\n' "$path" "$h" >> "$hashdb"
  done < "$curlist"
  rm -f "$curlist"
}

# -------------------------------------------------------------------------------------------------------------------------
# fsintegritylock/fsintegrityunlock guard against two overlapping scans (main loop cadence vs -fsintegrity cron vs forced) racing on the same manifest/state files.

fsintegritylock()
{
  local lockfile="$addonsdir/fsintegrity.lock" lockpid
  if [ -f "$lockfile" ]; then
    lockpid="$(cat "$lockfile" 2>/dev/null)"
    if [ -n "$lockpid" ] && [ "$lockpid" != "$$" ] && iocmonpid "$lockpid"; then
      return 1
    fi
  fi
  echo "$$" > "$lockfile"
  return 0
}

fsintegrityunlock()
{
  rm -f "$addonsdir/fsintegrity.lock"
}

# -------------------------------------------------------------------------------------------------------------------------
# runfsintegrityscan runs the full scan+cron+firewall diff under fsintegritylock, skipping (not racing) if already locked.

runfsintegrityscan()
{
  if ! fsintegritylock; then
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Filesystem-integrity scan skipped - another scan is already in progress." >> "$logfile"
    return 1
  fi
  checkfsintegrity
  checkcronbaseline
  checkentwarecron
  checkfirewallrules
  checketccritical
  fsintegrityunlock
  return 0
}

# -------------------------------------------------------------------------------------------------------------------------
# fsintegritycheck is the main-loop entry point

fsintegritycheck()
{
  fsintegrityranthiscycle=0

  [ "$enablefsintegrity" -eq 1 ] || return

  resolvestateroot
  [ -z "$stateroot" ] && return
  mkdir -m 755 -p "$stateroot"

  local stampfile="$stateroot/fs_last_check" nowepoch lastepoch duesec
  nowepoch=$(date +%s)
  lastepoch=0
  [ -f "$stampfile" ] && lastepoch="$(cat "$stampfile" 2>/dev/null)"
  [ -z "$lastepoch" ] && lastepoch=0
  duesec=$((fsintegrityhrs * 3600))

  if [ "$((nowepoch - lastepoch))" -ge "$duesec" ]; then
    if runfsintegrityscan; then
      fsintegrityranthiscycle=1
      echo "$nowepoch" > "$stampfile"
    fi
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# forcefsintegrity is the interactive on-demand baseline diff, mirroring forcefeeds

forcefsintegrity()
{
  clear
  echo -e "${CGreen}[Forcing Filesystem-Integrity Check ... Please stand by]${CClear}"
  echo ""

  resolvestateroot

  if [ -z "$stateroot" ]; then
    echo ""
    echo -e "${CRed}ERROR: No state storage location is available right now (external drive missing). Check skipped.${CClear}"
  else
    mkdir -m 755 -p "$stateroot"
    if runfsintegrityscan; then
      flushemailbatch
      date +%s > "$stateroot/fs_last_check"
      blanklineguard
      echo -e "  ${CGreen}*${CClear} Hashed/scanned ${CGreen}${fsscannedcount}${CClear} files across ${CGreen}${fsdircount}${CClear} watched directories"
      echo -e "  ${CGreen}*${CClear} Found ${CGreen}${fsnewcount}${CClear} new file(s), ${CGreen}${fsmodcount}${CClear} modified file(s), ${CGreen}${fsdelcount}${CClear} deletion(s) in critical paths, and ${CGreen}${fspermcount}${CClear} permission-only change(s) since the last scan"
      echo ""
      echo ""
      echo -e "${CGreen}Filesystem-integrity check complete.${CClear}"
    else
      echo ""
      echo -e "${CYellow}A filesystem-integrity scan is already in progress (likely the main loop's own periodic scan) - try again in a moment.${CClear}"
    fi
  fi

  echo ""
  read -rsp $'Press any key to continue...\n' -n1 key
  if [ "$timerpaused" -eq 1 ]; then renderdashboard; else timer=$timerloop; fi
}

# -------------------------------------------------------------------------------------------------------------------------
# otxiplink echoes the AlienVault OTX indicator-lookup URL for IPv4 address $1

otxiplink()
{
  echo "https://otx.alienvault.com/indicator/ip/$1"
}

# -------------------------------------------------------------------------------------------------------------------------
# daynumof echoes the days-since-1970-01-01 day number for calendar date $1/$2/$3 (year/month/day)

daynumof()
{
  awk -v y="$1" -v m="$2" -v d="$3" 'BEGIN {
    if (m <= 2) y -= 1
    era = (y >= 0 ? y : y - 399); era = int(era / 400)
    yoe = y - era * 400
    doy = int((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1
    doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
    print era * 146097 + doe - 719468
  }'
}

# -------------------------------------------------------------------------------------------------------------------------
# civilfromdaynum echoes the YYYY-MM-DD calendar date for day number $1 (the inverse of daynumof)

civilfromdaynum()
{
  awk -v z="$1" 'BEGIN {
    z += 719468
    era = int((z >= 0 ? z : z - 146096) / 146097)
    doe = z - era * 146097
    yoe = int((doe - int(doe / 1460) + int(doe / 36524) - int(doe / 146096)) / 365)
    y = yoe + era * 400
    doy = doe - (365 * yoe + int(yoe / 4) - int(yoe / 100))
    mp = int((5 * doy + 2) / 153)
    d = doy - int((153 * mp + 2) / 5) + 1
    m = mp + (mp < 10 ? 3 : -9)
    y += (m <= 2)
    printf "%04d-%02d-%02d\n", y, m, d
  }'
}

# -------------------------------------------------------------------------------------------------------------------------
# padexact prints $1 left-justified in a field of exactly $2 visible chars - unlike padright, never forces a minimum pad

padexact()
{
  local text="$1" width="$2" pad
  pad=$((width - ${#text}))
  [ "$pad" -lt 0 ] && pad=0
  printf '%s' "$text"
  printf '%*s' "$pad" ""
}

# -------------------------------------------------------------------------------------------------------------------------
# printotxreportrow prints one width-fixed, truncated 5-column row of the OTX report ($6=1 for header, $7=date for date-sort widths)

printotxreportrow()
{
  local c1="$1" c2="$2" c3="$3" c4="$4" c5="$5" header="${6:-0}"
  local w1=6 w2=16 w3=58 w4=28 w5=15
  [ "$7" = "date" ] && { w1=16; w2=15; w3=55; w4=25; w5=15; }

  [ "${#c1}" -gt "$w1" ] && c1="$(printf '%.*s' "$((w1-1))" "$c1")>"
  [ "${#c2}" -gt "$w2" ] && c2="$(printf '%.*s' "$((w2-1))" "$c2")>"
  [ "${#c3}" -gt "$w3" ] && c3="$(printf '%.*s' "$((w3-1))" "$c3")>"
  [ "${#c4}" -gt "$w4" ] && c4="$(printf '%.*s' "$((w4-1))" "$c4")>"
  [ "${#c5}" -gt "$w5" ] && c5="$(printf '%.*s' "$((w5-1))" "$c5")>"

  if [ "$header" -eq 1 ]; then
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}"; padexact "$c1" "$w1"
    echo -en "${CClear} | ${InvDkGray}${CWhite}"; padexact "$c2" "$w2"
    echo -en "${CClear} | ${InvDkGray}${CWhite}"; padexact "$c3" "$w3"
    echo -en "${CClear} | ${InvDkGray}${CWhite}"; padexact "$c4" "$w4"
    echo -e "${CClear} | ${InvDkGray}${CWhite}${c5}${CClear}"
  else
    echo -en "${InvGreen} ${CClear} ${CYellow}"; padexact "$c1" "$w1"
    echo -en "${CClear} | ${CGreen}"; padexact "$c2" "$w2"
    echo -en "${CClear} | ${CCyan}"; padexact "$c3" "$w3"
    echo -en "${CClear} | ${CWhite}"; padexact "$c4" "$w4"
    echo -e "${CClear} | ${CDkGray}${c5}${CClear}"
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# votxreport builds a date-ranged, paginated OTX report of conntrack feed matches ($1=quick: dashboard [N] last-7-days date view)

votxreport()
{
  local tab rangechoice todayy todaym todayd todayn startday endday startin endin rangelabel swap
  local oldifs syear smonth sday eyear emonth eday
  local pagesizeinput pagesize datafile spanfile rowtotal eventtotal logdays page totalpages pagestart pageend pagelabel r more key
  local rcount rip rsrc rfam rdevs rowcount rdevdisp devcount
  local quick=0 sortmode sortlabel returnlabel rkey rdate iptotal

  tab="$(printf '\t')"
  [ "$1" = "quick" ] && quick=1

  while true; do
    [ "$exitallmenus" -eq 1 ] && break
    if [ "$otxreportsort" = "date" ]; then sortlabel="Date"; else sortlabel="Frequency"; fi
    if [ "$quick" -eq 1 ]; then
      rangechoice=2
      sortmode="date"
      returnlabel="the IOCMON main screen"
    else
      sortmode="$otxreportsort"
      returnlabel="the OTX AlienVault Report menu"
      clear
      echo -e "${InvGreen} ${InvDkGray}${CWhite} OTX AlienVault Threat Report                                                                                                            ${CClear}"
      echo -e "${InvGreen} ${CClear}"
      echo -e "${InvGreen} ${CClear} Builds a report of outbound connections IOCMON's conntrack watch matched against a known-bad threat-feed IP, with a ready-made${CClear}"
      echo -e "${InvGreen} ${CClear} AlienVault OTX lookup link for each one - either grouped by destination and ranked by how often each was matched (Frequency sort), or${CClear}"
      echo -e "${InvGreen} ${CClear} listed occurrence by occurrence, newest first (Date sort). Each count reflects distinct alert events IOCMON actually logged to its${CClear}"
      echo -e "${InvGreen} ${CClear} Recent IoC Detections history (subject to its own 6-hour per-IP dedup window) - not a raw packet/hit counter the way a firewall's own${CClear}"
      echo -e "${InvGreen} ${CClear} ipset statistics are, so treat it as a frequency indicator rather than an exact tally. Only outbound matches are covered (a device here${CClear}"
      echo -e "${InvGreen} ${CClear} contacting a listed bad IP) - IOCMON's conntrack watch has no way to see unsolicited inbound traffic a listed bad IP sends toward this${CClear}"
      echo -e "${InvGreen} ${CClear} router.${CClear}"
      echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
      echo -e "${InvGreen} ${CClear}"
      echo -e "${InvGreen} ${CClear} Select a date range for this report:${CClear}"
      echo -e "${InvGreen} ${CClear}"
      echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(1)${CClear} : Today${CClear}"
      echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(2)${CClear} : Last 7 days${CClear}"
      echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(3)${CClear} : Last 30 days${CClear}"
      echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(4)${CClear} : All available history${CClear}"
      echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(5)${CClear} : Custom range (enter a start and end date)${CClear}"
      echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(6)${CClear} : Sort by: ${CGreen}${sortlabel}${CClear}"
      echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite} | ${CClear}"
      echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(e)${CClear} : Return to Configuration Menu${CClear}"
      echo -e "${InvGreen} ${CClear}"
      echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
      echo ""
      read -p "Please select? (1-6, e=Exit): " rangechoice
    fi

    set -- $(date +'%Y %m %d')
    todayy="$1"; todaym="$2"; todayd="$3"
    todayn="$(daynumof "$todayy" "$todaym" "$todayd")"

    case "$rangechoice" in
      1) startday="$todayn"; endday="$todayn" ;;
      2) startday=$((todayn - 6)); endday="$todayn" ;;
      3) startday=$((todayn - 29)); endday="$todayn" ;;
      4) startday=""; endday="" ;;
      5)
        echo ""
        read -p "Start date (YYYY-MM-DD, blank to cancel): " startin
        [ -z "$startin" ] && continue
        if ! validdatestr "$startin"; then
          echo -e "${CRed}\"$startin\" is not a valid YYYY-MM-DD date.${CClear}"
          sleep 2
          continue
        fi
        read -p "End date (YYYY-MM-DD, blank to cancel): " endin
        [ -z "$endin" ] && continue
        if ! validdatestr "$endin"; then
          echo -e "${CRed}\"$endin\" is not a valid YYYY-MM-DD date.${CClear}"
          sleep 2
          continue
        fi
        oldifs="$IFS"; IFS=-; set -- $startin; IFS="$oldifs"
        syear="$1"; smonth="$2"; sday="$3"
        oldifs="$IFS"; IFS=-; set -- $endin; IFS="$oldifs"
        eyear="$1"; emonth="$2"; eday="$3"
        startday="$(daynumof "$syear" "$smonth" "$sday")"
        endday="$(daynumof "$eyear" "$emonth" "$eday")"
        if [ "$startday" -gt "$endday" ]; then
          swap="$startday"; startday="$endday"; endday="$swap"
        fi
        ;;
      6)
        if [ "$otxreportsort" = "date" ]; then otxreportsort="frequency"; else otxreportsort="date"; fi
        saveconfig
        continue
        ;;
      [Ee]) break ;;
      [Ee]!) exitallmenus=1; break ;;
      *) continue ;;
    esac

    if [ -z "$startday" ]; then
      rangelabel="All available history"
    else
      rangelabel="$(civilfromdaynum "$startday") to $(civilfromdaynum "$endday")"
    fi

    if [ "$quick" -eq 1 ]; then
      pagesize=20
    else
      echo ""
      read -p "How many results per page? (10/20/50, blank defaults to 20): " pagesizeinput
      case "$pagesizeinput" in
        10|20|50) pagesize="$pagesizeinput" ;;
        *) pagesize=20 ;;
      esac
    fi

    resolvestateroot
    if [ -z "$stateroot" ] || [ -z "$(logall "$stateroot/ioc_alerts.log" | head -n1)" ]; then
      clear
      echo -e "${CRed}No IoC detection history is available yet (no feed storage location resolved, or nothing logged).${CClear}"
      echo ""
      read -rsp "Press any key to return to ${returnlabel}..."$'\n' -n1 key
      [ "$quick" -eq 1 ] && break
      continue
    fi

    logdays="$(logall "$stateroot/ioc_alerts.log" | awk -F'|' '
      BEGIN {
        split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", marr, " ")
        for (i = 1; i <= 12; i++) monthnum[marr[i]] = i
      }
      function daynum(y, m, d,   era, yoe, doy, doe) {
        if (m <= 2) y -= 1
        era = (y >= 0 ? y : y - 399); era = int(era / 400)
        yoe = y - era * 400
        doy = int((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1
        doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
        return era * 146097 + doe - 719468
      }
      {
        datepart = $1
        gsub(/^[ \t]+|[ \t]+$/, "", datepart)
        n = split(datepart, dp, " ")
        if (n < 3) next
        mon = monthnum[dp[1]] + 0
        if (mon == 0) next
        dn = daynum(dp[3] + 0, mon, dp[2] + 0)
        if (seen == 0 || dn < minday) minday = dn
        if (seen == 0 || dn > maxday) maxday = dn
        seen = 1
      }
      END { print (seen == 0 ? 1 : maxday - minday + 1) }
    ')"

    datafile="/tmp/iocmon_otxreport.$$"
    if [ "$sortmode" = "date" ]; then
      logall "$stateroot/ioc_alerts.log" | awk -F'|' -v startday="$startday" -v endday="$endday" '
        BEGIN {
          split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", marr, " ")
          for (i = 1; i <= 12; i++) monthnum[marr[i]] = i
        }
        function daynum(y, m, d,   era, yoe, doy, doe) {
          if (m <= 2) y -= 1
          era = (y >= 0 ? y : y - 399); era = int(era / 400)
          yoe = y - era * 400
          doy = int((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1
          doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
          return era * 146097 + doe - 719468
        }
        {
          if (NF < 5) next
          datepart = $1; kindpart = $2; indpart = $3; srcpart = $4; detpart = $5
          gsub(/^[ \t]+|[ \t]+$/, "", kindpart)
          if (kindpart != "conntrack") next
          gsub(/^[ \t]+|[ \t]+$/, "", datepart)
          gsub(/^[ \t]+|[ \t]+$/, "", indpart)
          gsub(/^[ \t]+|[ \t]+$/, "", srcpart)
          gsub(/^[ \t]+|[ \t]+$/, "", detpart)
          n = split(datepart, dp, " ")
          if (n < 3) next
          mon = monthnum[dp[1]] + 0
          if (mon == 0) next
          dn = daynum(dp[3] + 0, mon, dp[2] + 0)
          if (startday != "" && (dn < startday || dn > endday)) next
          split(indpart, parts, "->")
          if (parts[2] == "") next
          split(dp[4], tp, ":")
          key = dn * 86400 + (tp[1] + 0) * 3600 + (tp[2] + 0) * 60 + (tp[3] + 0)
          printf "%d\t%04d-%02d-%02d %s\t%s\t%s\t%s\t%s\n", key, dp[3] + 0, mon, dp[2] + 0, substr(dp[4], 1, 5), parts[2], srcpart, detpart, parts[1]
        }
      ' | sort -rn > "$datafile"
      rowtotal="$(wc -l < "$datafile" | tr -d ' ')"
      eventtotal="$rowtotal"
      iptotal="$(awk -F"$tab" '{print $3}' "$datafile" | sort -u | wc -l | tr -d ' ')"
    else
      logall "$stateroot/ioc_alerts.log" | awk -F'|' -v startday="$startday" -v endday="$endday" '
        BEGIN {
          split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", marr, " ")
          for (i = 1; i <= 12; i++) monthnum[marr[i]] = i
        }
        function daynum(y, m, d,   era, yoe, doy, doe) {
          if (m <= 2) y -= 1
          era = (y >= 0 ? y : y - 399); era = int(era / 400)
          yoe = y - era * 400
          doy = int((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1
          doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
          return era * 146097 + doe - 719468
        }
        {
          if (NF < 5) next
          datepart = $1; kindpart = $2; indpart = $3; srcpart = $4; detpart = $5
          gsub(/^[ \t]+|[ \t]+$/, "", kindpart)
          if (kindpart != "conntrack") next
          gsub(/^[ \t]+|[ \t]+$/, "", datepart)
          gsub(/^[ \t]+|[ \t]+$/, "", indpart)
          gsub(/^[ \t]+|[ \t]+$/, "", srcpart)
          gsub(/^[ \t]+|[ \t]+$/, "", detpart)
          n = split(datepart, dp, " ")
          if (n < 3) next
          mon = monthnum[dp[1]] + 0
          if (mon == 0) next
          dn = daynum(dp[3] + 0, mon, dp[2] + 0)
          if (startday != "" && (dn < startday || dn > endday)) next
          split(indpart, parts, "->")
          dstip = parts[2]
          if (dstip == "") next
          events++
          count[dstip]++
          if (index("," srcset[dstip] ",", "," parts[1] ",") == 0) srcset[dstip] = (srcset[dstip] == "" ? parts[1] : srcset[dstip] "," parts[1])
          if (index("," srcfeed[dstip] ",", "," srcpart ",") == 0) srcfeed[dstip] = (srcfeed[dstip] == "" ? srcpart : srcfeed[dstip] "," srcpart)
          if (index("," famset[dstip] ",", "," detpart ",") == 0) famset[dstip] = (famset[dstip] == "" ? detpart : famset[dstip] "," detpart)
        }
        END {
          for (ip in count) print count[ip] "\t" ip "\t" srcfeed[ip] "\t" famset[ip] "\t" srcset[ip] "\t" events
        }
      ' | sort -rn > "$datafile"
      rowtotal="$(wc -l < "$datafile" | tr -d ' ')"
      [ "$rowtotal" -gt 0 ] && eventtotal="$(awk -F"$tab" '{print $6}' "$datafile" | head -n1)"
      iptotal="$rowtotal"
    fi

    if [ "$rowtotal" -eq 0 ]; then
      rm -f "$datafile"
      clear
      echo -e "${CYellow}No conntrack threat-feed matches were logged in the selected date range (${rangelabel}).${CClear}"
      [ "$quick" -eq 1 ] && echo -e "${CDkGray}More reporting options (date ranges, page sizes, Frequency/Date sort) are under Configuration Menu item (5) OTX AlienVault Report.${CClear}"
      echo ""
      read -rsp "Press any key to return to ${returnlabel}..."$'\n' -n1 key
      [ "$quick" -eq 1 ] && break
      continue
    fi

    page=1
    totalpages=$(( (rowtotal + pagesize - 1) / pagesize ))
    [ "$totalpages" -lt 1 ] && totalpages=1
    more=1

    while [ "$more" -eq 1 ]; do
      [ "$exitallmenus" -eq 1 ] && break
      clear
      if [ "$page" -eq 0 ]; then
        pagestart=1; pageend="$rowtotal"; pagelabel="all $rowtotal entries"
      else
        pagestart=$(( (page - 1) * pagesize + 1 ))
        pageend=$(( page * pagesize ))
        [ "$pageend" -gt "$rowtotal" ] && pageend="$rowtotal"
        pagelabel="page ${page}/${totalpages}"
      fi

      echo -e "${InvGreen} ${InvDkGray}${CWhite} OTX AlienVault Threat Report                                                                                                            ${CClear}"
      echo -e "${InvGreen} ${CClear}"
      if [ "$sortmode" = "date" ]; then
        echo -e "${InvGreen} ${CClear} Date range: ${CGreen}${rangelabel}${CClear}  -  ${CGreen}${eventtotal}${CClear} alert event(s) across ${CGreen}${iptotal}${CClear} distinct IP(s), newest first  -  showing ${CGreen}${pagelabel}${CClear}${CClear}"
      else
        echo -e "${InvGreen} ${CClear} Date range: ${CGreen}${rangelabel}${CClear}  -  ${CGreen}${rowtotal}${CClear} distinct matched IP(s), ${CGreen}${eventtotal}${CClear} alert event(s) total  -  showing ${CGreen}${pagelabel}${CClear}${CClear}"
      fi
      echo -e "${InvGreen} ${CClear} Available Log Days: ${CGreen}${logdays}${CClear}${CClear}"
      echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
      if [ "$sortmode" = "date" ]; then
        printotxreportrow "Date / Time" "IP Address" "AlienVault OTX Lookup" "Feed Match / Family" "Local Device" 1 date
      else
        printotxreportrow "Alerts" "IP Address" "AlienVault OTX Lookup" "Feed Match / Family" "Local Device(s)" 1
      fi
      echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"

      r=0
      if [ "$sortmode" = "date" ]; then
        while IFS="$tab" read -r rkey rdate rip rsrc rfam rdevs; do
          r=$((r+1))
          [ "$r" -lt "$pagestart" ] && continue
          [ "$r" -gt "$pageend" ] && break
          printotxreportrow "$rdate" "$rip" "$(otxiplink "$rip")" "$rsrc / $rfam" "$rdevs" 0 date
        done < "$datafile"
      else
        while IFS="$tab" read -r rcount rip rsrc rfam rdevs _; do
          r=$((r+1))
          [ "$r" -lt "$pagestart" ] && continue
          [ "$r" -gt "$pageend" ] && break
          rowcount="$(printf '%5dx' "$rcount")"
          rdevdisp="$rdevs"
          case "$rdevdisp" in
            *,*)
              devcount=$(( $(printf '%s' "$rdevdisp" | awk -F',' '{print NF}') - 1 ))
              rdevdisp="${rdevdisp%%,*}+${devcount}"
              ;;
          esac
          printotxreportrow "$rowcount" "$rip" "$(otxiplink "$rip")" "$rsrc / $rfam" "$rdevdisp" 0
        done < "$datafile"
      fi

      echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
      [ "$quick" -eq 1 ] && echo -e "${InvGreen} ${CClear} ${CDkGray}More reporting options (date ranges, page sizes, Frequency/Date sort) are under Configuration Menu item (5) OTX AlienVault Report.${CClear}"
      echo ""
      if [ "$page" -eq 0 ] || [ "$page" -ge "$totalpages" ]; then
        read -rsp "Press any key to return to ${returnlabel}..."$'\n' -n1 key
        more=0
      else
        read -p "(Enter)=Next Page, (a)=Show All Remaining, (e)=Return to ${returnlabel}: " key
        case "$key" in
          [Aa]) page=0 ;;
          [Ee]) more=0 ;;
          [Ee]!) [ "$quick" -eq 0 ] && exitallmenus=1; more=0 ;;
          *) page=$((page + 1)) ;;
        esac
      fi
    done

    rm -f "$datafile"
    [ "$quick" -eq 1 ] && break
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# acknowledgealert clears the persistent alert_pending marker - the only way the red banner goes away.

acknowledgealert()
{
  clearalertpending
  renderdashboard
}

# -------------------------------------------------------------------------------------------------------------------------
# clearalertpending removes the alert marker and logs it: $1 = optional text naming where it was acknowledged from

clearalertpending()
{
  resolvestateroot
  if [ -n "$stateroot" ] && [ -f "$stateroot/alert_pending" ]; then
    rm -f "$stateroot/alert_pending"
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Security alert banner acknowledged$1." >> "$logfile"
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# addtodnsexception prompts for a numbered dns entry (from the "Recent IoC Detections" panel) and excepts its base domain.

addtodnsexception()
{
  if [ "$alertviewmode" != "ioc" ] || [ ! -s "$dnsnummapfile" ]; then
    renderdashboard
    return
  fi

  local maxnum num origkey domain base displayrange
  maxnum="$(wc -l < "$dnsnummapfile" | tr -d ' ')"
  if [ "$maxnum" -ge 10 ]; then displayrange="1-9, 0 for #10"; else displayrange="1-${maxnum}"; fi
  echo ""
  read -p "Please enter the corresponding log entry number of the domain to add to the DNS Exceptions List (${displayrange}, blank to cancel): " num

  if [ -z "$num" ]; then
    renderdashboard
    return
  fi
  origkey="$num"
  [ "$num" = "0" ] && num=10

  domain="$(awk -F'\t' -v n="$num" '$1==n{print $2}' "$dnsnummapfile")"
  if [ -z "$domain" ]; then
    echo -e "${CRed}No DNS entry numbered $origkey is currently shown (valid range: ${displayrange}).${CClear}"
    sleep 2
    renderdashboard
    return
  fi

  base="$(basedomain "$domain")"
  if ! validdomainentry "$base"; then
    echo -e "${CRed}Entry #$origkey is not a valid domain name - not added.${CClear}"
    sleep 2
    renderdashboard
    return
  fi
  if indnsexceptionlist "$base"; then
    echo -e "${CYellow}${base} is already in the DNS Exceptions list.${CClear}"
  else
    dnsexceptions="${dnsexceptions:+$dnsexceptions }$base"
    saveconfig
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Added $base to dnsexceptions via the (Z) hotkey (entry #$origkey: $domain)." >> "$logfile"
    echo ""
    echo -e "${CGreen}Added ${base} to the DNS Exceptions list.${CClear}"
  fi
  sleep 2
  renderdashboard
}

# -------------------------------------------------------------------------------------------------------------------------
# vioclog opens the full log behind whichever "Recent..." panel ($alertviewmode) is currently showing, in nano.

vioclog()
{
  resolvestateroot
  local viewfile="" emptymsg="No dropbear login-failure attempts have been logged yet."

  if [ "$alertviewmode" = "dropbear" ]; then
    [ -n "$stateroot" ] && viewfile="$stateroot/dropbear_attempts.log"
  elif [ "$alertviewmode" = "hash" ]; then
    emptymsg="No files have been checked against the malware-hash feed yet."
    [ -n "$stateroot" ] && viewfile="$stateroot/hash_check.log"
  elif [ "$alertviewmode" = "reputation" ]; then
    emptymsg="No AbuseIPDB reputation lookups have been logged yet."
    [ -n "$stateroot" ] && viewfile="$stateroot/reputation.log"
  else
    emptymsg="No IoC detections have been logged yet."
    [ -n "$stateroot" ] && viewfile="$stateroot/ioc_alerts.log"
  fi

  if [ -z "$viewfile" ] || [ -z "$(logall "$viewfile" | head -n1)" ]; then
    clear
    echo -e "${CYellow}${emptymsg}${CClear}"
    echo ""
    read -rsp $'Press any key to continue...\n' -n1 key
  else
    openlogview "$viewfile"
  fi
  renderdashboard
}

# -------------------------------------------------------------------------------------------------------------------------
# resolvecurrentviewfile sets $viewfile/$viewlabel to whichever log the "Recent..." panel/$alertviewmode is showing.

resolvecurrentviewfile()
{
  resolvestateroot
  viewfile=""; viewlabel="IoC Detections"

  if [ "$alertviewmode" = "dropbear" ]; then
    viewlabel="Dropbear Attempts"
    [ -n "$stateroot" ] && viewfile="$stateroot/dropbear_attempts.log"
  elif [ "$alertviewmode" = "hash" ]; then
    viewlabel="Hash-Check"
    [ -n "$stateroot" ] && viewfile="$stateroot/hash_check.log"
  elif [ "$alertviewmode" = "reputation" ]; then
    viewlabel="Reputation"
    [ -n "$stateroot" ] && viewfile="$stateroot/reputation.log"
  else
    [ -n "$stateroot" ] && viewfile="$stateroot/ioc_alerts.log"
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# clearcurrentlog wipes whichever log resolvecurrentviewfile resolves to, after an explicit (R) confirmation.

clearcurrentlog()
{
  resolvecurrentviewfile

  if [ -z "$viewfile" ]; then
    renderdashboard
    return
  fi

  clear
  echo -e "${CGreen}[Clear $viewlabel Log]${CClear}"
  echo ""
  echo -e "This erases $viewfile and its rotated copies. This is irreversible."
  echo ""
  if promptyn "Do you wish to proceed? [y/n]: "; then
    : > "$viewfile"
    logremoverotated "$viewfile"
    echo ""
    echo ""
    echo -e "${CGreen}Log cleared.${CClear}"
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: $viewlabel log cleared via (R) hotkey." >> "$logfile"
    sleep 1
  fi
  renderdashboard
}

# -------------------------------------------------------------------------------------------------------------------------
# clearcurrentlognow is (R!)'s no-confirmation instant clear - stays on the dashboard, no separate screen.

clearcurrentlognow()
{
  resolvecurrentviewfile

  if [ -n "$viewfile" ]; then
    : > "$viewfile"
    logremoverotated "$viewfile"
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: $viewlabel log cleared via (R!) instant-clear hotkey." >> "$logfile"
  fi
  renderdashboard
  [ -n "$viewfile" ] && echo -e "${CGreen}$viewlabel log cleared.${CClear}"
}

# -------------------------------------------------------------------------------------------------------------------------
# vfslastfile opens one of the four accumulating filesystem-integrity report files in nano

vfslastfile()
{
  local which="$1" viewfile="" label=""

  resolvestateroot
  if [ -n "$stateroot" ]; then
    case "$which" in
      1) viewfile="$stateroot/fs_last_new.txt"; label="new files" ;;
      2) viewfile="$stateroot/fs_last_modified.txt"; label="modified files" ;;
      3) viewfile="$stateroot/fs_last_deleted.txt"; label="deleted files" ;;
      4) viewfile="$stateroot/fs_last_permchanged.txt"; label="permission-changed files" ;;
    esac
  fi

  if [ -z "$viewfile" ] || [ -z "$(logall "$viewfile" | head -n1)" ]; then
    clear
    echo -e "${CYellow}No $label have been logged yet.${CClear}"
    echo ""
    read -rsp $'Press any key to continue...\n' -n1 key
  else
    openlogview "$viewfile"
  fi
  renderdashboard
}

# -------------------------------------------------------------------------------------------------------------------------
# simpickindicator sets simindicator/simsource/simfamily to one random real feed line; returns 1 when no feed data is loaded

simpickindicator()
{
  local candidatefile="" randline=""
  resolvefeedsroot
  if [ -n "$feedsroot" ] && [ -s "$feedsroot/ips.txt" ]; then
    candidatefile="$feedsroot/ips.txt"
  elif [ -n "$feedsroot" ] && [ -s "$feedsroot/domains.txt" ]; then
    candidatefile="$feedsroot/domains.txt"
  elif [ -n "$feedsroot" ] && [ -s "$feedsroot/hashes.txt" ]; then
    candidatefile="$feedsroot/hashes.txt"
  fi
  [ -n "$candidatefile" ] || return 1
  if [ "$enableabuseipdb" = "1" ] && [ -n "$abuseipdbapikey" ] && [ "$candidatefile" = "$feedsroot/ips.txt" ]; then
    randline="$(awk -F'|' 'BEGIN{srand()} $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {a[++n]=$0} END{if (n>0) print a[int(rand()*n)+1]}' "$candidatefile")"
  fi
  [ -z "$randline" ] && randline="$(awk 'BEGIN{srand()} {a[NR]=$0} END{if (NR>0) print a[int(rand()*NR)+1]}' "$candidatefile")"
  IFS='|' read -r simindicator simsource simfamily <<EOF
$randline
EOF
  return 0
}

# -------------------------------------------------------------------------------------------------------------------------
# testdetection picks one real indicator at random out of the currently loaded feeds

testdetection()
{
  clear
  echo -e "${CGreen}[Running Simulated Detection Test]${CClear}"
  echo ""

  if ! simpickindicator; then
    echo -e "${CRed}ERROR: No feed data is loaded yet - refresh feeds first, then try again.${CClear}"
  else
    echo -e "Simulating a detection of ${CGreen}${simindicator}${CClear} (from the ${CGreen}${simsource}${CClear} feed)..."
    echo ""
    raisealert "simulated" "$simindicator" "$simsource" "$simfamily - SIMULATED TEST via (T) hotkey, not a real detection"
    local testrepip="$repip" testrepreason="$repreason" testintel="$inteltag"
    flushemailbatch
    blanklineguard
    if [ "$enableabuseipdb" != "1" ] || [ -z "$abuseipdbapikey" ]; then
      echo -e "${CDkGray}AbuseIPDB reputation check is off - turn it on (Configuration Menu 2, items 12/13) to include it in this test.${CClear}"
    elif [ -n "$testrepip" ]; then
      echo -e "${CYellow}AbuseIPDB reputation check (SIMULATED TEST - live data):${CClear}"
      reputationemailblock "$testrepip" simulated | sed 's/<[^>]*>//g; /^$/d; /^=*$/d; /^AbuseIPDB reputation for/d; /^note:/d; s/&lt;/</g; s/&gt;/>/g; s/&amp;/\&/g; s/^/  /'
    else
      echo -e "${CYellow}AbuseIPDB reputation check (SIMULATED TEST): not checked - ${testrepreason:-no lookup was made}.${CClear}"
    fi
    [ -n "$testintel" ] && echo -e "${CYellow}Astraea certificate intel (information only):${CClear} ${testintel#Astraea }"
    echo ""
    echo -e "${CGreen}Simulated detection logged. Check the IoC log ((V) from the main screen), the Reputation log ((U)) and the red banner${CClear}"
    echo -e "${CGreen}on the main screen to confirm the alert pipeline is working; press (A) there to acknowledge it.${CClear}"
  fi

  echo ""
  read -rsp $'Press any key to continue...\n' -n1 key
  if [ "$timerpaused" -eq 1 ]; then renderdashboard; else timer=$timerloop; fi
}

# -------------------------------------------------------------------------------------------------------------------------
# schedulecron wires up the cru entries 

schedulecron()
{
  which cru >/dev/null 2>&1 || return

  local crulist updatecmd feedscmd fsintcmd
  crul
  crulist="$cruout"
  updatecmd="$schedulemin $schedulehrs * * * sh $apppath -autoupdate"
  feedscmd="0 */$feedupdatehrs * * * sh $apppath -updatefeeds"
  fsintcmd="0 */$fsintegrityhrs * * * sh $apppath -fsintegrity"

  local wantedlines=""
  if [ "$schedule" -eq 1 ]; then
    echo "$crulist" | grep -qF "$updatecmd #IOCMONUpdate#" || { $timeoutcmd$timeoutsec cru d IOCMONUpdate >/dev/null 2>&1; $timeoutcmd$timeoutsec cru a IOCMONUpdate "$updatecmd"; }
    wantedlines="cru a IOCMONUpdate \"$updatecmd\" # iocmon-cron
"
  else
    echo "$crulist" | grep -q '#IOCMONUpdate#' && $timeoutcmd$timeoutsec cru d IOCMONUpdate >/dev/null 2>&1
  fi
  echo "$crulist" | grep -qF "$feedscmd #IOCMONFeeds#" || { $timeoutcmd$timeoutsec cru d IOCMONFeeds >/dev/null 2>&1; $timeoutcmd$timeoutsec cru a IOCMONFeeds "$feedscmd"; }
  echo "$crulist" | grep -qF "$fsintcmd #IOCMONFsIntegrity#" || { $timeoutcmd$timeoutsec cru d IOCMONFsIntegrity >/dev/null 2>&1; $timeoutcmd$timeoutsec cru a IOCMONFsIntegrity "$fsintcmd"; }
  wantedlines="${wantedlines}cru a IOCMONFeeds \"$feedscmd\" # iocmon-cron
cru a IOCMONFsIntegrity \"$fsintcmd\" # iocmon-cron"

  local currentlines="" currentsorted wantedsorted
  [ -f /jffs/scripts/services-start ] && currentlines="$(grep '# iocmon-cron' /jffs/scripts/services-start)"
  currentsorted="$(printf '%s\n' "$currentlines" | sort)"
  wantedsorted="$(printf '%s\n' "$wantedlines" | sort)"
  [ "$currentsorted" = "$wantedsorted" ] && return

  if [ -f /jffs/scripts/services-start ]; then
    sed -i '/# iocmon-cron/d' /jffs/scripts/services-start
  else
    echo '#!/bin/sh' > /jffs/scripts/services-start
    chmod 755 /jffs/scripts/services-start
  fi

  printf '%s\n' "$wantedlines" >> /jffs/scripts/services-start
}

# -------------------------------------------------------------------------------------------------------------------------
# autostart adds/removes the post-mount hook that launches IOCMON's background SCREEN monitor on reboot

autostart()
{
  # one-time cleanup of the services-start hook, independent of post-mount's own state below
  if [ -f /jffs/scripts/services-start ] && grep -q '# iocmon-autostart' /jffs/scripts/services-start; then
    sed -i '/# iocmon-autostart/d' /jffs/scripts/services-start
  fi

  if [ ! -f /jffs/scripts/post-mount ]; then
    echo '#!/bin/sh' > /jffs/scripts/post-mount
    chmod 755 /jffs/scripts/post-mount
  fi

  local wantedline=""
  [ "$autostart" -eq 1 ] && wantedline="(sleep 30 && sh $apppath -screen -now) & # iocmon-autostart"

  local currentline=""
  currentline="$(grep '# iocmon-autostart' /jffs/scripts/post-mount 2>/dev/null)"
  [ "$currentline" = "$wantedline" ] && return

  grep -q '# iocmon-autostart' /jffs/scripts/post-mount 2>/dev/null && sed -i '/# iocmon-autostart/d' /jffs/scripts/post-mount
  [ -n "$wantedline" ] && echo "$wantedline" >> /jffs/scripts/post-mount
}

# -------------------------------------------------------------------------------------------------------------------------
# webuilog writes one line to the activity log: $1 = level, $2 = message

webuilog()
{
  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - $1: $2" >> "$logfile"
}

# -------------------------------------------------------------------------------------------------------------------------
# webuilockmenu and webuiunlockmenu take the lock Merlin add-ons share while editing the menu

webuilockmenu()
{
  exec 9>"$webuilockfile"
  which flock >/dev/null 2>&1 && flock -x 9
}

webuiunlockmenu()
{
  which flock >/dev/null 2>&1 && flock -u 9
  exec 9>&-
}

# -------------------------------------------------------------------------------------------------------------------------
# webuiremount binds the edited menu copy over the firmware's file

webuiremount()
{
  umount "$webuimenutree" 2>/dev/null
  mount -o bind "$webuimenutmp" "$webuimenutree"
}

# -------------------------------------------------------------------------------------------------------------------------
# webuifindslot echoes the userN.asp holding our page, or nothing

webuifindslot()
{
  local i
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    grep -qF "$webuimarker" "$webuiuserdir/user$i.asp" 2>/dev/null && { echo "user$i.asp"; return; }
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# webuiaddsection creates the shared Addons menu just before exclude:, unless it already exists

webuiaddsection()
{
  local ln block="/tmp/iocmon-webui-block.$$"
  grep -qF 'shared-jy/redirect.htm' "$webuimenutmp" && return 0
  if grep -q '^menuName: "Addons",$' "$webuimenutmp"; then
    webuilog "ERROR" "Web interface: an Addons menu exists without the shared Help & Support line - menu left unchanged."
    return 1
  fi
  ln="$(grep -n '^exclude:' "$webuimenutmp" | head -n 1 | cut -d: -f1)"
  if [ -z "$ln" ] || [ "$ln" -lt 2 ]; then
    webuilog "ERROR" "Web interface: no exclude: line in $webuimenutmp - menu left unchanged."
    return 1
  fi
  ln=$((ln - 1))
  cat > "$block" <<'BLOCKEND'
/**BEGIN:_AddOns_**/
,
{
menuName: "Addons",
index: "menu_Addons",
tab: [
{url: "javascript:var helpwindow=window.open('/ext/shared-jy/redirect.htm')", tabName: "Help & Support"},
{url: "NULL", tabName: "__INHERIT__"}
]
}
/**ENDIN:_AddOns_**/
BLOCKEND
  { head -n $((ln - 1)) "$webuimenutmp"; cat "$block"; tail -n +"$ln" "$webuimenutmp"; } > "$webuimenutmp.new"
  rm -f "$block"
  cat "$webuimenutmp.new" > "$webuimenutmp"
  rm -f "$webuimenutmp.new"
}

# -------------------------------------------------------------------------------------------------------------------------
# webuisharedlink links /www/ext/shared-jy to the JFFS shared folder as other add-ons do, replacing a folder only IOCMON made

webuisharedlink()
{
  if [ -d "$webuisharedweb" ] && [ ! -L "$webuisharedweb" ]; then
    case "$(ls -A "$webuisharedweb" 2>/dev/null)" in
      "") rmdir "$webuisharedweb" 2>/dev/null ;;
      redirect.htm) grep -qF "$webuiredirectmark" "$webuisharedweb/redirect.htm" 2>/dev/null && rm -f "$webuisharedweb/redirect.htm" && rmdir "$webuisharedweb" 2>/dev/null ;;
    esac
    if [ -d "$webuisharedweb" ] && [ ! -L "$webuisharedweb" ]; then
      webuilog "WARNING" "Web interface: $webuisharedweb is a folder, not the usual link to $webuisharedjffs, and holds other files - left unchanged. Add-on pages may not find their shared files."
    else
      webuilog "INFO" "Web interface: replaced the $webuisharedweb folder an earlier IOCMON version made with a link to $webuisharedjffs, so other add-ons find their shared files."
    fi
  fi
  mkdir -p "$webuisharedjffs"
  [ -e "$webuisharedweb" ] || [ -L "$webuisharedweb" ] || ln -s "$webuisharedjffs" "$webuisharedweb" 2>/dev/null
  [ -f "$webuiredirect" ] && return 0
  cat > "$webuiredirect" <<'REDIRECTEND'
<!-- IOCMON-WEBUI-REDIRECT -->
<html><head><meta http-equiv="refresh" content="0; url=https://www.snbforums.com/forums/asuswrt-merlin-addons.60/"/></head><body></body></html>
REDIRECTEND
}

# -------------------------------------------------------------------------------------------------------------------------
# webuiaddtab puts page $1 in the Addons menu, restoring the menu copy if anything looks wrong

webuiaddtab()
{
  local page="$1" ln
  [ -f "$webuimenutmp" ] || cp -f "$webuimenutree" "$webuimenutmp"
  cp -f "$webuimenutmp" "$webuimenubak"
  if ! webuiaddsection; then
    cat "$webuimenubak" > "$webuimenutmp"
    rm -f "$webuimenubak"
    return 1
  fi
  sed -i "/tabName: \"$webuitab\"/d" "$webuimenutmp"
  ln="$(grep -nF 'shared-jy/redirect.htm' "$webuimenutmp" | head -n 1 | cut -d: -f1)"
  [ -n "$ln" ] && sed -i "${ln}i {url: \"$page\", tabName: \"$webuitab\"}," "$webuimenutmp"
  if [ "$(grep -c "tabName: \"$webuitab\"" "$webuimenutmp")" != "1" ] || ! grep -q '^exclude:' "$webuimenutmp"; then
    webuilog "ERROR" "Web interface: the menu edit did not come out as expected - previous menu restored."
    cat "$webuimenubak" > "$webuimenutmp"
    webuiremount
    rm -f "$webuimenubak"
    return 1
  fi
  webuiremount
  rm -f "$webuimenubak"
}

# -------------------------------------------------------------------------------------------------------------------------
# webuimount copies the stored page into a slot and adds the tab; it runs when enabled and at every boot

webuimount()
{
  local page
  nvramget rc_support
  if ! printf '%s\n' "$nvramval" | grep -q am_addons; then
    webuilog "ERROR" "Web interface: this firmware has no add-on page support."
    return 1
  fi
  if [ ! -f /usr/sbin/helper.sh ] || [ ! -f "$webuipagefile" ]; then
    webuilog "ERROR" "Web interface: /usr/sbin/helper.sh or $webuipagefile is missing."
    return 1
  fi
  webuilockmenu
  page="$(webuifindslot)"
  if [ -z "$page" ]; then
    page="$(. /usr/sbin/helper.sh; am_get_webui_page "$webuipagefile"; echo "$am_webui_page")"
    if [ -z "$page" ] || [ "$page" = "none" ]; then
      webuiunlockmenu
      webuilog "ERROR" "Web interface: all add-on page slots are in use."
      return 1
    fi
  fi
  cp -f "$webuipagefile" "$webuiuserdir/$page"
  echo "$webuitab" > "$webuiuserdir/${page%.asp}.title"
  if ! webuiaddtab "$page"; then
    rm -f "$webuiuserdir/$page" "$webuiuserdir/${page%.asp}.title"
    webuiunlockmenu
    return 1
  fi
  webuiunlockmenu
  webuisharedlink
  mkdir -p "$webuidir"
  webuilog "INFO" "Web interface page mounted as $page."
}

# -------------------------------------------------------------------------------------------------------------------------
# webuiremove takes away the tab, page, data files and boot hook, leaving other add-ons' entries alone

webuiremove()
{
  local page
  webuilockmenu
  page="$(webuifindslot)"
  [ -n "$page" ] && rm -f "$webuiuserdir/$page" "$webuiuserdir/${page%.asp}.title"
  if [ -f "$webuimenutmp" ]; then
    sed -i "/tabName: \"$webuitab\"/d" "$webuimenutmp"
    if grep -q 'BEGIN:_AddOns_' "$webuimenutmp" && [ "$(awk '/BEGIN:_AddOns_/ { s = 1; next } /ENDIN:_AddOns_/ { s = 0 } s && /url:/ && !/shared-jy|"NULL"/ { n++ } END { print n + 0 }' "$webuimenutmp")" = "0" ]; then
      sed -i '/BEGIN:_AddOns_/,/ENDIN:_AddOns_/d' "$webuimenutmp"
      grep -qF "$webuiredirectmark" "$webuiredirect" 2>/dev/null && rm -f "$webuiredirect"
      if rmdir "$webuisharedjffs" 2>/dev/null && [ "$(readlink "$webuisharedweb" 2>/dev/null)" = "$webuisharedjffs" ]; then
        rm -f "$webuisharedweb"
      fi
      if [ ! -L "$webuisharedweb" ] && grep -qF "$webuiredirectmark" "$webuisharedweb/redirect.htm" 2>/dev/null; then
        rm -f "$webuisharedweb/redirect.htm"
        rmdir "$webuisharedweb" 2>/dev/null
      fi
    fi
    webuiremount
  fi
  webuiunlockmenu
  [ -f "$webuiservicesstart" ] && sed -i "/$webuitag/d" "$webuiservicesstart"
  [ -f "$webuiserviceevent" ] && sed -i "/$webuitag/d" "$webuiserviceevent"
  rm -rf "$webuidir"
  webuilog "INFO" "Web interface removed."
}

# -------------------------------------------------------------------------------------------------------------------------
# webuihooks adds whichever of the boot and button hook lines is missing, leaving other add-ons' lines alone

webuihooks()
{
  if ! grep -qF "$webuitag" "$webuiservicesstart" 2>/dev/null; then
    [ -f "$webuiservicesstart" ] || { echo '#!/bin/sh' > "$webuiservicesstart"; chmod 755 "$webuiservicesstart"; }
    echo "sh $apppath -webmount & $webuitag" >> "$webuiservicesstart"
  fi
  if ! grep -qF "$webuitag" "$webuiserviceevent" 2>/dev/null; then
    [ -f "$webuiserviceevent" ] || { echo '#!/bin/sh' > "$webuiserviceevent"; chmod 755 "$webuiserviceevent"; }
    echo "case \"\$1:\$2\" in start:iocmon*) sh $apppath -webaction \"\$2\" & ;; esac $webuitag" >> "$webuiserviceevent"
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# syncwebui makes the hooks and tab match enablewebui; saveconfig calls it, so they can't drift

syncwebui()
{
  if [ "${enablewebui:-0}" = "1" ]; then
    webuihooks
    [ -n "$(webuifindslot)" ] || webuimount
  elif grep -qF "$webuitag" "$webuiservicesstart" "$webuiserviceevent" 2>/dev/null || [ -d "$webuidir" ]; then
    webuiremove
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# webuifetchpage downloads the page for the current track, keeping any existing copy if the download is bad

webuifetchpage()
{
  local url="$iocmonrepostable/iocmon.asp" tmpfile="$webuipagefile.new"
  [ "$track" = "1" ] && url="$iocmonrepobeta/iocmon.asp"
  curl --silent --retry 3 --connect-timeout 10 --max-time 60 --retry-delay 1 --retry-all-errors --fail "$url" -o "$tmpfile"
  if [ "$?" -eq 0 ] && grep -qF "$webuimarker" "$tmpfile" 2>/dev/null; then
    mv -f "$tmpfile" "$webuipagefile"
    return 0
  fi
  rm -f "$tmpfile"
  webuilog "ERROR" "Web interface: could not download a valid page from $url."
  return 1
}

# -------------------------------------------------------------------------------------------------------------------------
# webuipagever prints the version in the stored page's marker line

webuipagever()
{
  sed -n "s/^$webuimarker v\([^ ]*\) -->.*/\1/p" "$webuipagefile" 2>/dev/null | head -n 1
}

# -------------------------------------------------------------------------------------------------------------------------
# webuisyncpage downloads the current track's page when the stored one isn't the version this script expects

webuisyncpage()
{
  [ "$(webuipagever)" = "$webuiversion" ] && return 0
  webuifetchpage || return 1
  webuilog "INFO" "Web interface page downloaded: v$(webuipagever)."
}

# -------------------------------------------------------------------------------------------------------------------------
# webuirefreshpage brings the stored page up to date, then puts it in the slot if the slot holds anything different

webuirefreshpage()
{
  local page
  [ "${enablewebui:-0}" = "1" ] || return 0
  webuisharedlink
  webuisyncpage
  page="$(webuifindslot)"
  [ -n "$page" ] && cmp -s "$webuipagefile" "$webuiuserdir/$page" && return 0
  webuimount
}

# -------------------------------------------------------------------------------------------------------------------------
# vwebuitoggle is 10.6 item 9: it explains the change, then installs or removes the web interface tab

vwebuitoggle()
{
  echo ""
  if [ "$enablewebui" -eq 1 ]; then
    echo -e "Remove the IOCMON tab from the router's web interface?"
    if promptyn "[y/n]: "; then
      echo ""
      enablewebui=0
      saveconfig
      echo ""
      echo -e "${CGreen}Removed. Reload the router's web page.${CClear}"
      sleep 2
    fi
    return
  fi
  echo -e "This adds an IOCMON tab under the Addons menu of the router's web interface, showing the same status, feeds and logs as this terminal"
  echo -e "script, with buttons to update feeds, scan the filesystem, simulate a detection, check for updates, start the monitor and acknowledge"
  echo -e "alerts. It needs a web interface login to view, and publishes no API keys, passwords or settings."
  echo ""
  echo -e "Enable the web interface tab?"
  promptyn "[y/n]: " || return
  echo ""
  webuienable
  sleep 3
}

# -------------------------------------------------------------------------------------------------------------------------
# webuienable installs the web interface tab, printing the result and leaving it off if any step fails

webuienable()
{
  nvramget rc_support
  if ! printf '%s\n' "$nvramval" | grep -q am_addons; then
    echo ""
    echo -e "${CRed}This firmware has no add-on page support - 386.1 or later is required.${CClear}"
    return 1
  fi
  webuisyncpage
  if [ ! -f "$webuipagefile" ]; then
    echo ""
    echo -e "${CRed}The web interface page could not be downloaded - see the activity log. Nothing was changed.${CClear}"
    return 1
  fi
  enablewebui=1
  saveconfig
  if [ -z "$(webuifindslot)" ]; then
    enablewebui=0
    saveconfig
    echo ""
    echo -e "${CRed}The tab could not be added - see the activity log. The web interface has been left off.${CClear}"
    return 1
  fi
  echo ""
  echo -e "${CGreen}Enabled. Reload the router's web page and open Addons > $webuitab. Its data appears after the next monitor cycle.${CClear}"
  return 0
}

# -------------------------------------------------------------------------------------------------------------------------
# webescape HTML-escapes published text, so a data file opened directly in a browser can't run anything from a log

webescape()
{
  sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

# -------------------------------------------------------------------------------------------------------------------------
# webcleanlog strips colour codes from stdin and escapes it for publishing

webcleanlog()
{
  local esc
  esc="$(printf '\033')"
  sed -e "s/${esc}\[[0-9;]*m//g" -e 's/\\e\[[0-9;]*m//g' | webescape
}

# -------------------------------------------------------------------------------------------------------------------------
# webrecent drops stdin lines dated before the recent window; lines without a date pass through, and $1 = all turns it off

webrecent()
{
  [ "$1" = "all" ] && { cat; return; }
  awk -v y="$(date +%Y)" -v m="$(date +%m)" -v d="$(date +%d)" -v keep="$webuirecentdays" '
    function dn(yy, mm, dd, era, yoe, doy) {
      if (mm <= 2) yy -= 1
      era = int(yy / 400)
      yoe = yy - era * 400
      doy = int((153 * (mm + (mm > 2 ? -3 : 9)) + 2) / 5) + dd - 1
      return era * 146097 + yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy - 719468
    }
    BEGIN {
      n = split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", names, " ")
      for (i = 1; i <= n; i++) mon[names[i]] = i
      cutoff = dn(y + 0, m + 0, d + 0) - keep
    }
    ($1 in mon) && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9][0-9][0-9][0-9]$/ && dn($3 + 0, mon[$1], $2 + 0) < cutoff { next }
    { print }'
}

# -------------------------------------------------------------------------------------------------------------------------
# webpublishlog copies the tail of log $2 to data file $1, only when the log changed: $3 = lines kept, $4 = all to skip the date window

webpublishlog()
{
  local dst="$webuidir/$1.htm" sigfile="$webuidir/.$1.sig" sig
  if [ -z "$2" ] || { [ ! -f "$2" ] && [ ! -f "$2.1" ]; }; then
    rm -f "$dst" "$sigfile"
    return
  fi
  sig="$(ls -ln "$2" "$2.1" 2>/dev/null)"
  [ -f "$dst" ] && [ "$sig" = "$(cat "$sigfile" 2>/dev/null)" ] && return
  { echo "iocmon=1"; logall "$2" | tail -n "$3" | webrecent "$4" | webcleanlog; } > "$webuidir/.$1.tmp.$$"
  mv -f "$webuidir/.$1.tmp.$$" "$dst"
  echo "$sig" > "$sigfile"
}

# -------------------------------------------------------------------------------------------------------------------------
# webfetched prints a feed file's last fetch time from its timestamp, or nothing: $1 = file in the feeds meta folder

webfetched()
{
  [ -f "$feedsroot/meta/$1" ] && date -r "$feedsroot/meta/$1" +'%b %d %H:%M' 2>/dev/null
}

# -------------------------------------------------------------------------------------------------------------------------
# webpublish writes the web interface's data files from the values collectstatus just gathered, once per main-loop cycle

webpublish()
{
  [ "${enablewebui:-0}" = "1" ] || return
  [ -d "$webuidir" ] || return
  local updatever="" pendingcount="" pendingsummary="" fserrcount=0 fserrfirst="" dnsstate="off"
  [ "$track" = "0" ] && [ "$UpdateNotify" != "0" ] && updatever="$DLversion"
  [ "$track" = "1" ] && [ "$BUpdateNotify" != "0" ] && updatever="$Bversion"
  if [ -n "$updatever" ] && [ "$(vercompare "$updatever" "$version")" != "gt" ]; then updatever=""; fi
  if [ -n "$stateroot" ]; then
    if [ -f "$stateroot/alert_pending" ]; then
      pendingcount="$(sed -n '1p' "$stateroot/alert_pending" 2>/dev/null)"
      pendingsummary="$(sed -n '2p' "$stateroot/alert_pending" 2>/dev/null)"
    fi
    if [ -s "$stateroot/fs_scan_errors.txt" ]; then
      fserrcount="$(wc -l < "$stateroot/fs_scan_errors.txt" | tr -d ' ')"
      fserrfirst="$(head -n1 "$stateroot/fs_scan_errors.txt")"
    fi
  fi
  if [ "$enablednswatch" -eq 1 ]; then
    dnsstate="waiting"
    if dnsusesagh; then dnsstate="adguardhome"; aghanylogin || dnsstate="nologin"; elif dnsquerylogenabled; then dnsstate="dnsmasq"; fi
  fi
  {
    echo "iocmon=1"
    echo "version=$version"
    echo "webui=$webuiversion"
    echo "ts=$(date +%s)"
    echo "time=$(date +'%b %d %Y %X')"
    echo "loop=$timerloop"
    echo "hostname=$(_GetLAN_HostName_)"
    echo "model=$routermodel"
    echo "uptime=$routeruptime"
    echo "track=$track"
    echo "updatever=$updatever"
    echo "pendingcount=$pendingcount"
    echo "pendingsummary=$pendingsummary"
    echo "alertlevel=$alertlevel"
    echo "lastalert=$lastalert"
    echo "todaycount=$todaycount"
    echo "reputation=$(stripansi "$(reputationstatus 200)")"
    echo "feedstotal=$feedsindicatorcount"
    echo "feedhrs=$feedupdatehrs"
    echo "feedsoldest=$feedsoldest"
    echo "feedsources=$feedsbreakdown"
    echo "fetched_fd=$(webfetched feodo.meta)"
    echo "fetched_sh=$(webfetched spamhaus_drop.meta)"
    echo "fetched_na=$(webfetched netapi_ips.meta)"
    echo "fetched_uh=$(webfetched urlhaus.meta)"
    echo "fetched_tf=$(webfetched threatfox.meta)"
    echo "fetched_qf=$(webfetched qfeeds.last)"
    echo "conntrackon=$enableconntrackwatch"
    echo "conntrackchecked=$conntrackchecked"
    echo "conntracklast=$conntracklastcheck"
    echo "dnsstate=$dnsstate"
    echo "dnschecked=$dnsqueriedcount"
    echo "dnslast=$dnslastcheck"
    echo "dnslog=$dnslogshort"
    echo "dnsfailover=$aghfailover"
    echo "authon=$enableauthwatch"
    echo "authchecked=$authchecked"
    echo "authlast=$authlastcheck"
    echo "nvramon=$enablenvramwatch"
    echo "nvramvars=$(echo "$nvramwatchvars" | wc -w | tr -d ' ')"
    echo "nvramlast=$nvramlastcheck"
    echo "fson=$enablefsintegrity"
    echo "fsbaseline=$fsbaselinecount"
    echo "fshrs=$fsintegrityhrs"
    echo "fserrcount=$fserrcount"
    echo "fserrfirst=$fserrfirst"
    echo "email=$enablealertemail"
    echo "ratelimit=$ratelimit"
    echo "cron=$cronscheduled"
    echo "storage=$(stripansi "$drivestatus")"
    echo "drivefree=$drivefreespace"
  } | webescape > "$webuidir/.status.tmp"
  mv -f "$webuidir/.status.tmp" "$webuidir/status.htm"
  webpublishlogs
  webfullexpire
}

# -------------------------------------------------------------------------------------------------------------------------
# webpublishlogs refreshes every published log and list; a web job also calls it, so results show without waiting for a cycle

webpublishlogs()
{
  webpublishlog ioc "${stateroot:+$stateroot/ioc_alerts.log}" "$webuirecentrows"
  webpublishlog dropbear "${stateroot:+$stateroot/dropbear_attempts.log}" "$webuirecentrows"
  webpublishlog hash "${stateroot:+$stateroot/hash_check.log}" "$webuirecentrows"
  webpublishlog reputation "${stateroot:+$stateroot/reputation.log}" "$webuirecentrows"
  webpublishlog fssummary "${stateroot:+$stateroot/fs_scan_summary.txt}" 60 all
  webpublishlog fsnew "${stateroot:+$stateroot/fs_last_new.txt}" 200 all
  webpublishlog fsmod "${stateroot:+$stateroot/fs_last_modified.txt}" 200 all
  webpublishlog fsdel "${stateroot:+$stateroot/fs_last_deleted.txt}" 200 all
  webpublishlog fsperm "${stateroot:+$stateroot/fs_last_permchanged.txt}" 200 all
}

# -------------------------------------------------------------------------------------------------------------------------
# webjobwrite publishes the current web job for the page: $1 = state, $2 = message

webjobwrite()
{
  {
    echo "iocmon=1"
    echo "id=$webjobid"
    echo "action=$webjobaction"
    echo "state=$1"
    echo "started=$webjobstart"
    echo "time=$(date +'%b %d %Y %X')"
    echo "msg=$2"
  } | webescape > "$webuidir/.job.tmp"
  mv -f "$webuidir/.job.tmp" "$webuidir/job.htm"
}

# -------------------------------------------------------------------------------------------------------------------------
# iocmonpid succeeds when pid $1 is a live IOCMON process, so a stale pid reused by another program never holds a lock

iocmonpid()
{
  { tr '\0' ' ' < "/proc/$1/cmdline"; } 2>/dev/null | grep -q iocmon
}

# -------------------------------------------------------------------------------------------------------------------------
# webjoblock takes the one-job lock atomically, replacing a lock whose owner has died

webjoblock()
{
  local lockpid
  mkdir "$webuijoblock" 2>/dev/null && { echo "$$" > "$webuijoblock/pid"; return 0; }
  lockpid="$(cat "$webuijoblock/pid" 2>/dev/null)"
  [ -n "$lockpid" ] && kill -0 "$lockpid" 2>/dev/null && return 1
  rm -rf "$webuijoblock"
  mkdir "$webuijoblock" 2>/dev/null && { echo "$$" > "$webuijoblock/pid"; return 0; }
  return 1
}

# -------------------------------------------------------------------------------------------------------------------------
# webjobfeeds is the Update Feeds button: a forced refresh under the feed lock

webjobfeeds()
{
  resolvefeedsroot
  if [ -z "$feedsroot" ]; then webjobmsg="No feed storage is available - the external drive may be missing."; return 1; fi
  mkdir -m 755 -p "$feedsroot/meta"
  if ! feedslock; then webjobmsg="A feed refresh is already in progress."; return 1; fi
  updatefeeds force
  date +%s > "$feedsroot/meta/.last_update"
  feedsunlock
  webjobmsg="$feedokcount source(s) ok, $feedfailcount failed."
  [ "$feedfailcount" -eq 0 ]
}

# -------------------------------------------------------------------------------------------------------------------------
# webjobscan is the Scan Filesystem button: the same scan as the (I) hotkey

webjobscan()
{
  resolvestateroot
  if [ -z "$stateroot" ]; then webjobmsg="No state storage is available - the external drive may be missing."; return 1; fi
  mkdir -m 755 -p "$stateroot"
  if ! runfsintegrityscan; then webjobmsg="A filesystem scan is already in progress."; return 1; fi
  flushemailbatch
  date +%s > "$stateroot/fs_last_check"
  webjobmsg="$fsscannedcount file(s) scanned: $fsnewcount new, $fsmodcount modified, $fsdelcount deleted, $fspermcount permission-only."
}

# -------------------------------------------------------------------------------------------------------------------------
# webjobsimulate is the Simulate Detection button: the same test alert as the (T) hotkey

webjobsimulate()
{
  if ! simpickindicator; then webjobmsg="No feed data is loaded yet - update feeds first."; return 1; fi
  raisealert "simulated" "$simindicator" "$simsource" "$simfamily - SIMULATED TEST via the web interface, not a real detection"
  flushemailbatch
  rm -f "$abuseipdbcyclefile"
  webjobmsg="Simulated a detection of $simindicator from the $simsource feed."
}

# -------------------------------------------------------------------------------------------------------------------------
# webupdatepublish checks the current track and writes update.htm; webupdatelatest holds the result

webupdatepublish()
{
  local available=0
  updatecheck
  betacheck
  webupdatelatest="$DLversion"
  [ "$track" = "1" ] && webupdatelatest="$Bversion"
  [ -n "$webupdatelatest" ] || return 1
  [ "$(vercompare "$webupdatelatest" "$version")" = "gt" ] && available=1
  { echo "iocmon=1"; echo "latest=$webupdatelatest"; echo "available=$available"; echo "checked=$(date +%s)"; } | webescape > "$webuidir/.update.tmp.$$"
  mv -f "$webuidir/.update.tmp.$$" "$webuidir/update.htm"
}

# -------------------------------------------------------------------------------------------------------------------------
# webautocheck runs when the page opens: it checks quietly, and only if the last result is old enough, using the router's clock

webautocheck()
{
  local checked age
  [ -f "$updatingfile" ] && return
  checked="$(sed -n 's/^checked=//p' "$webuidir/update.htm" 2>/dev/null)"
  if [ -n "$checked" ]; then
    age=$(($(date +%s) - checked))
    [ "$age" -ge 0 ] && [ "$age" -lt "$webuicheckage" ] && return
  fi
  webupdatepublish
}

# -------------------------------------------------------------------------------------------------------------------------
# webjobcheck is the Check for Update button

webjobcheck()
{
  if ! webupdatepublish; then webjobmsg="The update server could not be reached."; return 1; fi
  case "$(vercompare "$webupdatelatest" "$version")" in
    gt) webjobmsg="Update available: v$version to v$webupdatelatest." ;;
    lt) webjobmsg="IOCMON v$version is newer than the published v$webupdatelatest." ;;
    *) webjobmsg="IOCMON v$version is up to date." ;;
  esac
}

# -------------------------------------------------------------------------------------------------------------------------
# webjobupdate is the Install Update button: current track only, never to an older version, and a bad download is rolled back

webjobupdate()
{
  local remoteversion remotelabel remoteurl backup="/tmp/iocmon.sh.webupdate"
  updatecheck
  betacheck
  if [ "$track" = "1" ] && [ -z "$Bversion" ]; then webjobmsg="The Beta update server could not be reached."; return 1; fi
  resolveupdatesource
  if [ -z "$remoteversion" ]; then webjobmsg="The update server could not be reached."; return 1; fi
  if [ "$(vercompare "$remoteversion" "$version")" != "gt" ]; then webjobmsg="IOCMON v$version is already current."; return 0; fi
  echo > "$updatingfile"
  cp -f "$apppath" "$backup"
  downloadiocmonupdate "$remoteurl" "$remotelabel"
  case "$?" in
    0) ;;
    2) rm -f "$updatingfile" "$backup"; webjobmsg="The download failed validation. IOCMON v$version was left in place."; return 1 ;;
    *) rm -f "$updatingfile" "$backup"; webjobmsg="The download failed. IOCMON v$version was left in place."; return 1 ;;
  esac
  if ! scriptfilevalid "$apppath"; then
    cp -f "$backup" "$apppath"
    chmod 755 "$apppath"
    rm -f "$updatingfile" "$backup"
    webuilog "ERROR" "The web interface update to v$remoteversion failed validation - restored v$version."
    webjobmsg="The download failed validation. IOCMON v$version was restored."
    return 1
  fi
  touch "$restartpendingfile"
  rm -f "$updatingfile" "$backup"
  sh "$apppath" -webmount
  webjobmsg="Installed v$(ondiskversion). A running monitor restarts into it at its next cycle, then this page reloads."
}

# -------------------------------------------------------------------------------------------------------------------------
# webjobfull is the Full History button: it publishes one whole log for a short time, because data files sit in RAM

webjobfull()
{
  local src="" dst="$webuidir/full-$webfulllog.htm"
  resolvestateroot
  if [ -z "$stateroot" ]; then webjobmsg="No state storage is available - the external drive may be missing."; return 1; fi
  case "$webfulllog" in
    ioc) src="ioc_alerts.log" ;;
    dropbear) src="dropbear_attempts.log" ;;
    hash) src="hash_check.log" ;;
    reputation) src="reputation.log" ;;
  esac
  rm -f "$webuidir"/full-*.htm
  if [ -z "$(logall "$stateroot/$src" | head -n1)" ]; then webjobmsg="Nothing has been logged yet."; return 1; fi
  { echo "iocmon=1"; logall "$stateroot/$src" | tail -n "$webuifullrows" | webcleanlog; } > "$webuidir/.full.tmp"
  mv -f "$webuidir/.full.tmp" "$dst"
  date +%s > "$webuidir/.full.ts"
  webjobmsg="$(($(wc -l < "$dst") - 1)) row(s) loaded."
}

# -------------------------------------------------------------------------------------------------------------------------
# webfullexpire removes a Full History copy once it is old enough, so it doesn't sit in RAM

webfullexpire()
{
  local made
  made="$(cat "$webuidir/.full.ts" 2>/dev/null)"
  [ -n "$made" ] || return
  if [ "$(($(date +%s) - made))" -ge "$webuifullkeep" ]; then rm -f "$webuidir"/full-*.htm "$webuidir/.full.ts"; fi
}

# -------------------------------------------------------------------------------------------------------------------------
# webjobstart is the Start Monitor button: the main loop's singleton lock stays the only guard against a second copy

webjobstart()
{
  local pidfile="$addonsdir/iocmon.pid" monpid waited=0
  monpid="$(cat "$pidfile" 2>/dev/null)"
  if [ -n "$monpid" ] && iocmonpid "$monpid"; then webjobmsg="The monitor is already running. It may be paused or open in a menu."; return 0; fi
  if [ ! -x /opt/sbin/screen ]; then webjobmsg="The Entware screen package is required to start the monitor from here."; return 1; fi
  TERM="${TERM:-xterm}"; export TERM
  sh "$apppath" -screen -now
  while [ "$waited" -lt 15 ]; do
    monpid="$(cat "$pidfile" 2>/dev/null)"
    if [ -n "$monpid" ] && iocmonpid "$monpid"; then webjobmsg="Monitor started. Data updates after its first cycle."; return 0; fi
    sleep 1
    waited=$((waited + 1))
  done
  webjobmsg="The monitor did not start. Check for a stale SCREEN session with screen -ls."
  return 1
}

# -------------------------------------------------------------------------------------------------------------------------
# webaction runs one fixed web button from service-event: $1 = its event name, which is never used as anything but a match

webaction()
{
  local rc
  [ "${enablewebui:-0}" = "1" ] && [ -d "$webuidir" ] || return
  case "$1" in
    iocmonack)
      clearalertpending " from the web interface"
      sed -i -e 's/^pendingcount=.*/pendingcount=/' -e 's/^pendingsummary=.*/pendingsummary=/' "$webuidir/status.htm" 2>/dev/null
      return ;;
    iocmonautocheck) webautocheck; return ;;
    iocmonfeeds) webjobaction="feeds" ;;
    iocmonscan) webjobaction="scan" ;;
    iocmonsimulate) webjobaction="simulate" ;;
    iocmoncheck) webjobaction="check" ;;
    iocmonstart) webjobaction="start" ;;
    iocmonupdate) webjobaction="update" ;;
    iocmonfullioc) webjobaction="full"; webfulllog="ioc" ;;
    iocmonfulldropbear) webjobaction="full"; webfulllog="dropbear" ;;
    iocmonfullhash) webjobaction="full"; webfulllog="hash" ;;
    iocmonfullreputation) webjobaction="full"; webfulllog="reputation" ;;
    *) webuilog "WARNING" "Ignored an unknown web interface action."; return ;;
  esac
  if ! webjoblock; then
    webuilog "INFO" "Web interface $webjobaction request refused - another job is running."
    return
  fi
  webjobid="$(date +%s)-$$"
  webjobstart="$(date +%s)"
  webuilog "INFO" "Web interface job started: $webjobaction."
  webjobwrite "running" ""
  if [ -f "$updatingfile" ]; then
    webjobmsg="An IOCMON update is in progress. Try again in a moment."
    rc=1
  else
    "webjob$webjobaction"
    rc=$?
  fi
  resolvestateroot
  webpublishlogs
  if [ "$rc" -eq 0 ]; then webjobwrite "done" "$webjobmsg"; else webjobwrite "failed" "$webjobmsg"; fi
  webuilog "INFO" "Web interface job finished: $webjobaction: $webjobmsg"
  rm -rf "$webuijoblock"
}

# -------------------------------------------------------------------------------------------------------------------------
# vresetdefaults erases iocmon.cfg and restarts the script fresh, so every setting reverts to its script default.

vresetdefaults()
{
  clear
  echo -e "${InvGreen} ${InvDkGray}${CWhite} 6. Reset IOCMON to Default Settings                                                                                                     ${CClear}"
  echo -e "${InvGreen} ${CClear}"
  echo -e "${InvGreen} ${CClear} This erases $config and restarts IOCMON: every toggle, threshold, and list (watched/excluded paths, cron/DNS${CClear}"
  echo -e "${InvGreen} ${CClear} exceptions, feed sources, etc.) reverts to its shipped default, and you will be walked through initial setup (drive selection) again.${CClear}"
  echo -e "${InvGreen} ${CClear} This is irreversible.${CClear}"
  echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
  echo ""
  echo -e "Do you wish to proceed?"
  if promptyn "[y/n]: "; then
    if [ "$enablednswatch" -eq 1 ]; then
      echo ""
      disablednsquerylogging
      [ "$dnsforcefilelog" -eq 1 ] && disablednsfilelogging
    fi
    [ "$enableskynetimport" -eq 1 ] && removeskynetimports
    [ "$enablewebui" -eq 1 ] && webuiremove
    [ "$logfile" != "$jffslogfile" ] && relocatelogfile "$jffslogfile"
    rm -f "$config"
    echo ""
    echo -e "${CGreen}Configuration erased. Restarting IOCMON with default settings...${CClear}"
    sleep 2
    exec sh "$apppath" -noswitch
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# applyimportedconfig sources $1 (an .ioc export), preserves this router's own drive label, and re-saves.

applyimportedconfig()
{
  local importfile="$1" keepextdrivelabel="$extdrivelabel" keeplogfilepath="$logfilepath" newfswatchdirs="" entry oldlabel translated=0
  local keeptfkey="$threatfoxapikey" keepuhkey="$urlhausapikey" keepqfkey="$qfeedsapikey" keepaipdbkey="$abuseipdbapikey" keepaghcred="$aghcred" keepaghcred2="$aghcred2" keptkeys=""

  alertlevel=""; alertfeedonly=0
  . "$importfile"
  migratealertlevel

  extdrivelabel="$keepextdrivelabel"
  logfilepath="$keeplogfilepath"
  [ -z "$threatfoxapikey" ] && [ -n "$keeptfkey" ] && { threatfoxapikey="$keeptfkey"; keptkeys="${keptkeys:+$keptkeys, }ThreatFox"; }
  [ -z "$urlhausapikey" ] && [ -n "$keepuhkey" ] && { urlhausapikey="$keepuhkey"; keptkeys="${keptkeys:+$keptkeys, }URLhaus"; }
  [ -z "$qfeedsapikey" ] && [ -n "$keepqfkey" ] && { qfeedsapikey="$keepqfkey"; keptkeys="${keptkeys:+$keptkeys, }Q-Feeds"; }
  [ -z "$abuseipdbapikey" ] && [ -n "$keepaipdbkey" ] && { abuseipdbapikey="$keepaipdbkey"; keptkeys="${keptkeys:+$keptkeys, }AbuseIPDB"; }
  [ -z "$aghcred" ] && [ -n "$keepaghcred" ] && { aghcred="$keepaghcred"; keptkeys="${keptkeys:+$keptkeys, }AdGuard Home"; }
  [ -z "$aghcred2" ] && [ -n "$keepaghcred2" ] && { aghcred2="$keepaghcred2"; keptkeys="${keptkeys:+$keptkeys, }backup AdGuard Home"; }
  [ -z "$urlhausapikey" ] && enableurlhaus=0
  [ -z "$threatfoxapikey" ] && enablethreatfox=0
  [ -z "$qfeedsapikey" ] && enableqfeeds=0
  [ -z "$abuseipdbapikey" ] && enableabuseipdb=0
  resolveiocmonroot
  dnslogpath=""
  aghurl=""
  aghurl2=""
  dnsforcefilelog=0
  enableskynetimport=0
  enablewebui=0

  for entry in $fswatchdirs; do
    case "$entry" in
      /tmp/mnt/*)
        [ -z "$extdrivelabel" ] && { translated=1; continue; }
        oldlabel="${entry#/tmp/mnt/}"
        oldlabel="${oldlabel%%/*}"
        if [ "$oldlabel" != "$extdrivelabel" ]; then
          entry="/tmp/mnt/$extdrivelabel${entry#/tmp/mnt/$oldlabel}"
          translated=1
        fi
        ;;
    esac
    newfswatchdirs="${newfswatchdirs:+$newfswatchdirs }$entry"
  done
  fswatchdirs="$newfswatchdirs"

  saveconfig
  [ "$translated" -eq 1 ] && echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Imported fswatchdirs entries were adjusted to this router's own drive label." >> "$logfile"
  [ -n "$keptkeys" ] && echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: The imported settings had no $keptkeys API key(s) - this router's own key(s) were kept." >> "$logfile"
  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Settings imported from $importfile." >> "$logfile"
}

# -------------------------------------------------------------------------------------------------------------------------
# exportiocmonconfig writes the current config (optionally without API keys) to a user-chosen .ioc file.

exportiocmonconfig()
{
  clear
  echo -e "${CGreen}[Export IOCMON Settings]${CClear}"
  echo ""

  local defaultdir defaultname exportpath includekeys=0

  resolveiocmonroot
  if [ -n "$iocmonroot" ] && [ -d "$iocmonroot" ]; then defaultdir="$iocmonroot"; else defaultdir="$addonsdir"; fi
  defaultname="$(_GetLAN_HostName_)-config-export.ioc"

  echo -e "Default: ${CGreen}${defaultdir}/${defaultname}${CClear}"
  read -p "Full path and filename to export to (blank = default above): " exportpath
  [ -z "$exportpath" ] && exportpath="$defaultdir/$defaultname"

  if [ -f "$exportpath" ]; then
    echo ""
    echo -e "${CYellow}${exportpath} already exists.${CClear}"
    echo -e "Overwrite it?"
    if ! promptyn "[y/n]: "; then
      echo ""
      echo -e "${CRed}Export cancelled.${CClear}"
      read -rsp $'Press any key to continue...\n' -n1 key
      return
    fi
  fi

  if [ ! -d "$(dirname "$exportpath")" ]; then
    echo ""
    echo -e "${CRed}ERROR: Directory $(dirname "$exportpath") does not exist.${CClear}"
    read -rsp $'Press any key to continue...\n' -n1 key
    return
  fi

  echo ""
  echo -e "Include the URLhaus/ThreatFox/Q-Feeds/AbuseIPDB API keys and the AdGuard Home logins in this export?"
  if promptyn "[y/n]: "; then includekeys=1; else includekeys=0; fi

  { echo "# IOCMON settings export - v$version - $(date +'%b %d %Y %X') - $(_GetLAN_HostName_)"
    cat "$config"
  } > "$exportpath"
  [ "$includekeys" -eq 0 ] && sed -i -E 's/^threatfoxapikey=.*/threatfoxapikey=""/; s/^urlhausapikey=.*/urlhausapikey=""/; s/^qfeedsapikey=.*/qfeedsapikey=""/; s/^abuseipdbapikey=.*/abuseipdbapikey=""/; s/^aghcred=.*/aghcred=""/; s/^aghcred2=.*/aghcred2=""/' "$exportpath"

  echo ""
  echo -e "${CGreen}Exported to ${exportpath}${CClear}"
  echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Settings exported to $exportpath (API keys $([ "$includekeys" -eq 1 ] && echo included || echo excluded))." >> "$logfile"
  echo ""
  read -rsp $'Press any key to continue...\n' -n1 key
}

# -------------------------------------------------------------------------------------------------------------------------
# importiocmonconfig confirms, applies, then restarts into a user-chosen .ioc file's settings.

importiocmonconfig()
{
  clear
  echo -e "${CGreen}[Import IOCMON Settings]${CClear}"
  echo ""
  read -p "Full path to the .ioc file to import: " importfile

  if [ -z "$importfile" ] || [ ! -f "$importfile" ]; then
    echo ""
    echo -e "${CRed}ERROR: File not found: $importfile${CClear}"
    read -rsp $'Press any key to continue...\n' -n1 key
    return
  fi

  if ! grep -q '^timerloop=' "$importfile" || ! grep -q '^fswatchdirs=' "$importfile"; then
    echo ""
    echo -e "${CRed}ERROR: $importfile does not look like a valid IOCMON settings export.${CClear}"
    read -rsp $'Press any key to continue...\n' -n1 key
    return
  fi

  echo ""
  echo -e "This overwrites your current IOCMON configuration with the contents of:"
  echo -e "  ${CGreen}${importfile}${CClear}"
  echo ""
  echo -e "Your feed storage drive selection is kept as-is; everything else is replaced. This is irreversible."
  echo ""
  promptyn "Do you wish to proceed? [y/n]: " || return

  applyimportedconfig "$importfile"

  echo ""
  echo ""
  echo -e "${CGreen}Import complete. Restarting IOCMON with the imported settings...${CClear}"
  sleep 2
  exec sh "$apppath" -noswitch
}

# -------------------------------------------------------------------------------------------------------------------------
# vimportexport is the Import/Export IOCMON Settings submenu.

vimportexport()
{
  while true; do
    [ "$exitallmenus" -eq 1 ] && break
    clear
    echo -e "${InvGreen} ${InvDkGray}${CWhite} 7. Import/Export IOCMON Settings                                                                                                        ${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Export the current configuration (every toggle, threshold, and exclusion list) to a portable .ioc file, or import one from a previous${CClear}"
    echo -e "${InvGreen} ${CClear} install or another router.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(1)${CClear} : Export current settings to a file${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(2)${CClear} : Import settings from a file${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite} | ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(e)${CClear} : Return to Configuration Menu${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (1-2, e=Exit): " sel
    case "$sel" in
      1) exportiocmonconfig ;;
      2) importiocmonconfig ;;
      [Ee]) break ;;
      [Ee]!) exitallmenus=1; break ;;
      *) ;;
    esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# vupdate checks both tracks (per TAILMON's own vupdate), lets the user switch tracks, and downloads/installs the chosen one.

vupdate()
{
  local trackdisp tracklabel remoteversion remotelabel remoteurl selupdate

  while true; do
    [ "$exitallmenus" -eq 1 ] && break
    updatecheck
    betacheck

    if [ "$track" = "0" ]; then trackdisp="Stable"; tracklabel="STABLE"; else trackdisp="Beta"; tracklabel="BETA"; fi

    clear
    echo -e "${InvGreen} ${InvDkGray}${CWhite} 8. Update IOCMON                                                                                                                        ${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Checks for and installs the latest IOCMON script from your preferred Stable or Beta track.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CWhite} Stable Track${CClear}"
    echo -e "${InvGreen} ${CClear} Local Version:       ${CGreen}$version${CClear}"
    echo -e "${InvGreen} ${CClear} Official Version:    ${CGreen}${DLversion:-unknown}${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CWhite} Beta Track${CClear}"
    echo -e "${InvGreen} ${CClear} Local Version:       ${CGreen}$version${CClear}"
    echo -e "${InvGreen} ${CClear} Latest Beta Version: ${CGreen}${Bversion:-unknown}${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Your subscribed track: ${CGreen}$trackdisp${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""

    resolveupdatesource

    if [ -z "$remoteversion" ]; then
      echo -e "The latest ${CGreen}${tracklabel}${CClear} version could not be checked. Download anyway, or change tracks?"
    else
      case "$(vercompare "$version" "$remoteversion")" in
        eq) echo -e "You are on the latest ${CGreen}${tracklabel}${CClear} version! Download & overwrite, or change tracks?" ;;
        gt) echo -e "No update available: v$version is newer than the latest ${CGreen}${tracklabel}${CClear} version (v$remoteversion). Download & go back to v$remoteversion, or change tracks?" ;;
        *) echo -e "A new ${CGreen}${tracklabel}${CClear} version (v$remoteversion) is available! Download & upgrade, or change tracks?" ;;
      esac
    fi
    read -p "(Stable = 0, Beta = 1, Download = y/n, e=Exit): " selupdate
    case "$selupdate" in
      0) track=0; saveconfig ;;
      1) track=1; saveconfig ;;
      [Yy])
        echo ""
        echo -e "Downloading IOCMON ${CGreen}${remotelabel}${CClear}..."
        if downloadiocmonupdate "$remoteurl" "$remotelabel"; then
          echo -e "${CGreen}Download successful.${CClear}"
          echo ""
          read -rsp $'Press any key to restart IOCMON...\n' -n1 key
          exec sh "$apppath" -noswitch
        else
          echo -e "${CRed}ERROR: Download failed - check network connectivity and try again.${CClear}"
          echo ""
          read -rsp $'Press any key to continue...\n' -n1 key
        fi
        ;;
      [Ee]!)
        exitallmenus=1
        if [ "$timerpaused" -eq 1 ]; then renderdashboard; else timer=$timerloop; fi
        return
        ;;
      [Nn]|[Ee])
        if [ "$timerpaused" -eq 1 ]; then renderdashboard; else timer=$timerloop; fi
        return
        ;;
      *) ;;
    esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# installentwarepkg confirms, then opkg update + installs every package name in $1, logging the result.

installentwarepkg()
{
  local pkgs="$1" pkg
  clear
  echo -e "${InvGreen} ${InvDkGray}${CWhite} Install Optional Entware Component(s)                                                                                                   ${CClear}"
  echo -e "${InvGreen} ${CClear}"
  echo -e "${InvGreen} ${CClear} About to install: ${CGreen}${pkgs}${CClear}"
  echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
  echo ""

  if [ ! -x /opt/bin/opkg ]; then
    echo -e "${CRed}ERROR: Entware was not found on this router.${CClear}"
    echo -e "Please install Entware using the AMTM utility first, then return to this menu."
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - ERROR: Entware was not found installed on router. Please investigate." >> "$logfile"
    echo ""
    read -rsp $'Press any key to continue...\n' -n1 key
    return
  fi

  echo -e "Ready to install?"
  if promptyn "[y/n]: "; then
    echo ""
    echo -e "${CGreen}Updating Entware package lists...${CClear}"
    echo ""
    opkg update
    for pkg in $pkgs; do
      echo ""
      echo -e "Installing Entware ${CGreen}${pkg}${CClear}..."
      echo ""
      opkg install "$pkg"
    done
    echo ""
    echo -e "${CGreen}Install complete.${CClear}"
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Optional Entware package(s) installed: $pkgs" >> "$logfile"
    echo ""
    read -rsp $'Press any key to continue...\n' -n1 key
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# timedprompt shows $2 with a live countdown of $3 seconds; mode $1 "yn" returns 0 yes, 1 no, 2 no answer; "key" ends on any key

timedprompt()
{
  local mode="$1" text="$2" deadline left key rc answer=""
  deadline=$(( $(date +%s) + $3 ))
  while true; do
    left=$(( deadline - $(date +%s) ))
    if [ "$left" -le 0 ]; then
      printf '\n'
      return 2
    fi
    if [ "$mode" = "yn" ]; then
      printf '\r\033[K%s %ss: %s' "$text" "$left" "$answer"
    else
      printf '\r\033[K%s %ss...' "$text" "$left"
    fi
    key=""
    read -rs -n 1 -t 1 key
    rc=$?
    if [ "$rc" -ne 0 ] && [ -z "$key" ]; then
      [ "$(date +%s)" -le $(( deadline - left )) ] && sleep 1
      continue
    fi
    if [ "$mode" != "yn" ]; then
      printf '\n'
      return 0
    fi
    case "$key" in
      [Yy]) answer="y" ;;
      [Nn]) answer="n" ;;
      "") [ -n "$answer" ] && break ;;
      *) answer="" ;;
    esac
  done
  printf '\n'
  [ "$answer" = "y" ]
}

# -------------------------------------------------------------------------------------------------------------------------
# checktimeoutbin offers at startup to install the required Entware timeout binary, carrying on without it after 60s or a no

checktimeoutbin()
{
  local yn key
  _SetUpTimeoutCmdVars_
  [ -f /opt/bin/timeout ] && return 0

  setupbanner "Required Entware Component: timeout" \
    "IOCMON needs Entware's ${CGreen}timeout${CClear} command (package ${CGreen}${timeoutpkg}${CClear}). On some firmware builds an 'nvram' or 'cru' call can hang and" \
    "never return. timeout stops such a call after 10 seconds, so IOCMON keeps running and reuses the last value it read. Without it, a" \
    "hung call stalls IOCMON until it is restarted. It can also be installed later from Configuration Menu item 9."

  if [ ! -x /opt/bin/opkg ]; then
    echo -e "${CRed}ERROR: Entware was not found on this router.${CClear}"
    echo -e "Please install Entware using the AMTM utility, then restart IOCMON to install ${timeoutpkg}."
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: The required Entware package $timeoutpkg is missing and Entware is not installed - nvram and cru calls run without a time limit." >> "$logfile"
    echo ""
    timedprompt key "Press any key to continue - continuing on its own in" 60
    return 1
  fi

  echo -e "Install ${timeoutpkg} now? Type y or n, then press Enter. IOCMON carries on without it when the countdown ends."
  timedprompt yn "[y/n] - continuing without it in" 60
  yn=$?
  echo ""
  case "$yn" in
    0)
      echo -e "${CGreen}Updating Entware package lists...${CClear}"
      echo ""
      opkg update
      echo ""
      echo -e "Installing Entware ${CGreen}${timeoutpkg}${CClear}..."
      echo ""
      opkg install "$timeoutpkg"
      echo ""
      _SetUpTimeoutCmdVars_
      if [ -f /opt/bin/timeout ]; then
        echo -e "${CGreen}Install complete.${CClear}"
        echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Required Entware package installed: $timeoutpkg" >> "$logfile"
        sleep 2
        return 0
      fi
      echo -e "${CRed}ERROR: ${timeoutpkg} did not install - IOCMON will carry on without it.${CClear}"
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - ERROR: The required Entware package $timeoutpkg failed to install - nvram and cru calls run without a time limit." >> "$logfile"
      sleep 3
      ;;
    *)
      [ "$yn" = 2 ] && echo -e "${CYellow}No answer within 60 seconds.${CClear}"
      echo ""
      echo -e "${CYellow}Continuing without ${timeoutpkg}. You will be asked again the next time IOCMON starts.${CClear}"
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: The required Entware package $timeoutpkg is not installed - nvram and cru calls run without a time limit." >> "$logfile"
      sleep 2
      ;;
  esac
  return 1
}

# -------------------------------------------------------------------------------------------------------------------------
# ventwarecomponents explains and optionally installs every Entware package IOCMON can use, all of them optional.

ventwarecomponents()
{
  local screenstatus findstatus jqstatus timeoutstatus selentware

  while true; do
    [ "$exitallmenus" -eq 1 ] && break
    clear
    if [ -x /opt/sbin/screen ]; then screenstatus="${CGreen}Installed${CClear}"; else screenstatus="${CYellow}Not installed${CClear}"; fi
    if [ -x /opt/bin/find ]; then findstatus="${CGreen}Installed${CClear}"; else findstatus="${CYellow}Not installed${CClear}"; fi
    if which jq >/dev/null 2>&1; then jqstatus="${CGreen}Installed${CClear}"; else jqstatus="${CYellow}Not installed${CClear}"; fi
    if [ -f /opt/bin/timeout ]; then timeoutstatus="${CGreen}Installed${CClear}"; else timeoutstatus="${CRed}Not installed${CClear}"; fi

    echo -e "${InvGreen} ${InvDkGray}${CWhite} 9. Optional Entware Components                                                                                                          ${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Items 1-3 are optional: IOCMON runs fully in a reduced mode without them, and each one only unlocks or speeds up one specific feature.${CClear}"
    echo -e "${InvGreen} ${CClear} Item 4 is required. All of this needs Entware itself, already installed via the AMTM utility.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(1)${CClear} : screen             : ${screenstatus}${CClear}"
    echo -e "${InvGreen} ${CClear}       Runs IOCMON continuously in the background so it survives an SSH disconnect and can autostart on reboot. Required specifically for${CClear}"
    echo -e "${InvGreen} ${CClear}       the -screen/autostart feature - without it, IOCMON only runs in the foreground while you stay attached to it.${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(2)${CClear} : findutils          : ${findstatus}${CClear}"
    echo -e "${InvGreen} ${CClear}       Full GNU find, used by the filesystem-integrity scan. Without it, IOCMON falls back to the router's own built-in BusyBox find${CClear}"
    echo -e "${InvGreen} ${CClear}       automatically - scans still run correctly either way, this only affects how efficiently they run.${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(3)${CClear} : jq                 : ${jqstatus}${CClear}"
    echo -e "${InvGreen} ${CClear}       A JSON parser used for ThreatFox's API data. Without it, IOCMON reads the same fields with its own built-in parser - ThreatFox${CClear}"
    echo -e "${InvGreen} ${CClear}       still works fully either way, jq is simply the more robust parser if abuse.ch ever changes the format.${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(4)${CClear} : timeout            : ${timeoutstatus} ${CWhite}(required)${CClear}"
    echo -e "${InvGreen} ${CClear}       Stops an 'nvram' or 'cru' call that hangs, a known firmware issue, after 10 seconds so IOCMON keeps running and reuses the last${CClear}"
    echo -e "${InvGreen} ${CClear}       value it read. Installed from the ${timeoutpkg} package. Without it, one hung call can stall IOCMON until it is restarted.${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(5)${CClear} : Install all of the above${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite} | ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(e)${CClear} : Return to Configuration Menu${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (1-5, e=Exit): " selentware
    case "$selentware" in
      1) installentwarepkg "screen" ;;
      2) installentwarepkg "findutils" ;;
      3) installentwarepkg "jq" ;;
      4) installentwarepkg "$timeoutpkg"; _SetUpTimeoutCmdVars_ ;;
      5) installentwarepkg "screen findutils jq $timeoutpkg"; _SetUpTimeoutCmdVars_ ;;
      [Ee]) break ;;
      [Ee]!) exitallmenus=1; break ;;
      *) ;;
    esac
  done

  if [ "$timerpaused" -eq 1 ]; then renderdashboard; else timer=$timerloop; fi
}

# -------------------------------------------------------------------------------------------------------------------------
# vuninstall removes every trace of IOCMON from the router

vuninstall()
{
  clear
  echo -e "${InvGreen} ${InvDkGray}${CWhite} 11. Uninstall Utility                                                                                                                  ${CClear}"
  echo -e "${InvGreen} ${CClear}"
  echo -e "${InvGreen} ${CClear} This will remove IOCMON from your router: the script, its cron jobs, autostart hook, and its config/log directory. This action is${CClear}"
  echo -e "${InvGreen} ${CClear} irreversible.${CClear}"
  echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
  echo ""
  echo -e "Do you wish to proceed?"
  if promptyn "[y/n]: "; then
    echo ""
    if [ "$enablednswatch" -eq 1 ]; then
      disablednsquerylogging
      [ "$dnsforcefilelog" -eq 1 ] && disablednsfilelogging
    fi
    [ "$enableskynetimport" -eq 1 ] && removeskynetimports
    [ "$enablewebui" -eq 1 ] && webuiremove
    echo -e "${CGreen}Removing scheduled cron jobs...${CClear}"
    $timeoutcmd$timeoutsec cru d IOCMONUpdate >/dev/null 2>&1
    $timeoutcmd$timeoutsec cru d IOCMONFeeds >/dev/null 2>&1
    $timeoutcmd$timeoutsec cru d IOCMONFsIntegrity >/dev/null 2>&1

    if [ -f /jffs/scripts/services-start ]; then
      sed -i '/# iocmon-cron/d' /jffs/scripts/services-start
      sed -i '/# iocmon-autostart/d' /jffs/scripts/services-start
    fi
    if [ -f /jffs/scripts/post-mount ]; then
      sed -i '/# iocmon-autostart/d' /jffs/scripts/post-mount
    fi

    echo -e "${CGreen}Removing shell alias...${CClear}"
    if [ -f /jffs/configs/profile.add ]; then
      sed -i '/# added by iocmon/d' /jffs/configs/profile.add
    fi

    echo ""
    echo -e "Also remove the IoC feed cache and detection state from the external drive?"
    if promptyn "[y/n]: "; then
      resolveiocmonroot
      [ -n "$iocmonroot" ] && rm -rf "$iocmonroot"
    fi

    echo ""
    echo -e "${CGreen}Removing IOCMON configuration and logs...${CClear}"
    rm -rf "$addonsdir"

    echo -e "${CGreen}Removing IOCMON script...${CClear}"
    rm -f "$apppath"

    echo ""
    echo -e "${CGreen}IOCMON has been uninstalled. Goodbye!${CClear}"
    echo ""
    sleep 2
    # Must stay last: this ends the session the uninstall itself may be running in
    [ -x /opt/sbin/screen ] && /opt/sbin/screen -S iocmon -X quit >/dev/null 2>&1
    exit 0
  else
    echo ""
    echo -e "${CClear}Uninstall cancelled."
    sleep 1
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# Begin main commandline switch logic
# -------------------------------------------------------------------------------------------------------------------------

laststatustext=""
lastinputtext=""
winchpending=0
progressfirstdraw=0
driveunmountedalerted=0
skynetmissinglogged=0
dnsquerylogwarned=0
dnsquerymissingwarned=0
bypassscreentimer=0
conntrackchecked=0; conntracklastcheck=""
dnschecked=0; dnslastcheck=""
authchecked=0; authlastcheck=""
alertviewmode="ioc"
dnsnummapfile="/tmp/iocmon_dns_nummap.$$"
abuseipdbcyclefile="/tmp/iocmon_aipdb_cycle.$$"
dnscheckpointcache=""; dnsanchorcache=""; authsyncsig=""; authlastlinecount=0
dnslogresolved=""; dnslogreason=""; dnslogautofile=""; dnslogautotime=0; dnslogautoreason=""; dnslognonecount=0; dnslognonewarned=0; dnslogannounced=""; dnslogshort=""
aghapiwarned=""; aghjqwarned=0; aghcursorcache=""; aghqueries=0; aghskippedblocked=0
aghslot=1; aghfailover=0; aghapiwarned2=""; aghcursorcache2=""
timerpaused=0
exitallmenus=0

scriptreplacewarned=0

_SetUpTimeoutCmdVars_
_SetLAN_HostName_

if [ ! -d "$addonsdir" ]; then
  mkdir -m 755 -p "$addonsdir"
fi

if [ "$1" = "amtmupdate" ]; then
    shift
    [ -f "$config" ] && . "$config"
    resolvelogfile
    if [ "${track:-0}" = "1" ]; then
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: AMTM update request ignored - this install is subscribed to the Beta track, which AMTM only ever installs Stable for; use Configuration Menu (6) to update a Beta install instead." >> "$logfile"
      exit 0
    fi
    ScriptUpdateFromAMTM "$@"
    exit "$?"
fi

# Check and see if any commandline option is being used
if [ $# -eq 0 ]; then
    clear
    exec sh "$apppath" -noswitch
    exit 0
fi

# Check to see if a second parameter is bypassing the SCREEN launch timer
if [ "$2" == "-now" ]; then
  bypassscreentimer=1
fi

# Check and see if an invalid commandline option is being used
if [ "$1" == "-h" ] || [ "$1" == "-help" ] || [ "$1" == "-setup" ] || [ "$1" == "-noswitch" ] || [ "$1" == "-autoupdate" ] || [ "$1" == "-email" ] || [ "$1" == "-screen" ] || [ "$1" == "-updatefeeds" ] || [ "$1" == "-fsintegrity" ] || [ "$1" == "-webmount" ] || [ "$1" == "-webaction" ]; then
    clear
else
    clear
    echo ""
    echo "IOCMON v$version"
    echo ""
    echo "Exiting due to invalid commandline options!"
    echo "(run 'iocmon.sh -h' for help)"
    echo ""
    echo -e "${CClear}"
    exit 0
fi

# Check to see if the help option is being called
if [ "$1" == "-h" ] || [ "$1" == "-help" ]; then
  clear
  echo ""
  echo "IOCMON v$version Commandline Option Usage:"
  echo ""
  echo "iocmon -h | -help"
  echo "iocmon -setup"
  echo "iocmon -email"
  echo "iocmon -screen [-now]"
  echo "iocmon -updatefeeds"
  echo "iocmon -fsintegrity"
  echo ""
  echo " -h | -help (this output)"
  echo " -setup (displays the configuration menu)"
  echo " -email (sends a test email to confirm AMTM notifications are configured correctly)"
  echo " -screen (runs the monitoring loop in a background SCREEN session)"
  echo " -screen -now (as above, but skips the launch countdown)"
  echo " -updatefeeds (cron-callable: refreshes IoC feeds once and exits)"
  echo " -fsintegrity (cron-callable: runs one filesystem-integrity + cron-baseline check and exits)"
  echo ""
  echo -e "${CClear}"
  exit 0
fi

# Check to see if the setup option is being called. Initial setup (including the interactive drive picker)
if [ "$1" == "-setup" ]; then
    logoNM
    if [ -f "$config" ]; then
      . "$config"
      resolvelogfile
    else
      initialsetup
    fi
    checktimeoutbin
    vsetup
    exit 0
fi

# Check to see if a test email is being requested.
if [ "$1" == "-email" ]; then
    if [ ! -f "$config" ]; then
      echo "IOCMON has not completed initial setup yet - run 'iocmon.sh -setup' first."
      exit 1
    fi
    . "$config"
    resolvelogfile
    enablealertemail=1
    sendmessage 1 "test" "Test alert" "manual" "requested via -email switch"
    exit 0
fi

# Check to see if autoupdate is being called (cron-callable).
if [ "$1" == "-autoupdate" ]; then
    if [ ! -f "$config" ]; then
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: Autoupdate skipped - IOCMON has not completed initial setup yet." >> "$logfile"
      exit 1
    fi
    . "$config"
    resolvelogfile
    updatecheck
    betacheck
    if [ "$updateiocm" -eq 1 ]; then
      resolveupdatesource
      if [ -n "$remoteversion" ] && [ "$version" != "$remoteversion" ]; then
        echo > "$updatingfile"
        if downloadiocmonupdate "$remoteurl" "$remotelabel"; then
          touch "$restartpendingfile"
        fi
        rm -f "$updatingfile" >/dev/null 2>&1
      fi
    fi
    exit 0
fi

# Check to see if a one-shot feed refresh is being called (cron-callable via the IOCMONFeeds cru entry).
if [ "$1" == "-updatefeeds" ]; then
    if [ ! -f "$config" ]; then
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: -updatefeeds skipped - IOCMON has not completed initial setup yet." >> "$logfile"
      exit 1
    fi
    . "$config"
    resolvelogfile
    checkfeedupdate
    checklogrotate
    exit 0
fi

# Check to see if the boot hook is rebuilding the web interface tab, which lives in RAM
if [ "$1" == "-webmount" ]; then
    [ -f "$config" ] || exit 0
    . "$config"
    resolvelogfile
    if [ "${enablewebui:-0}" = "1" ]; then
      webuihooks
      webuimount
      webuirefreshpage
    fi
    exit 0
fi

# Check to see if a web interface button has fired through the service-event hook
if [ "$1" == "-webaction" ]; then
    [ -f "$config" ] || exit 0
    exec >/dev/null 2>&1
    . "$config"
    resolvelogfile
    webaction "$2"
    exit 0
fi

# Check to see if a one-shot filesystem-integrity check is being called (cron-callable via IOCMONF -fsintegrity)
if [ "$1" == "-fsintegrity" ]; then
    if [ ! -f "$config" ]; then
      echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - WARNING: -fsintegrity skipped - IOCMON has not completed initial setup yet." >> "$logfile"
      exit 1
    fi
    . "$config"
    resolvelogfile
    fsintegritycheck
    flushemailbatch
    exit 0
fi

# -------------------------------------------------------------------------------------------------------------------------
# screenreattach tries to reattach to $1's SCREEN session, but only if a controlling terminal is actually available.

screenreattach()
{
  if [ -t 0 ]; then
    /opt/sbin/screen -dr "$1"
  else
    echo -e "${CClear}No controlling terminal to reattach to - IOCMON is running detached in SCREEN session \"$1\"."
  fi
}

# Check to see if the screen option is being called and run operations normally using the screen utility
if [ "$1" == "-screen" ]; then
    if [ ! -x /opt/sbin/screen ]; then
      clear
      echo -e "${CGreen}Starting IOCMON under a normal SSH Terminal session...${CClear}"
      echo ""
      echo -e "${CYellow}WARNING: The Entware 'screen' package is required for -screen mode.${CClear}"
      echo -e "Optionally install it with command: opkg install screen"
      echo ""
      for screenfallbacksec in 5 4 3 2 1; do
        printf "\rContinuing in %ds..." "$screenfallbacksec"
        sleep 1
      done
      echo ""
      exec sh "$apppath" -noswitch
    fi

    /opt/sbin/screen -wipe >/dev/null 2>&1 # Kill any dead screen sessions
    sleep 1
    ScreenSess=$(/opt/sbin/screen -ls | grep "iocmon" | awk '{print $1}' | cut -d . -f 1)
      if [ -z "$ScreenSess" ]; then
        if [ "$bypassscreentimer" == "1" ]; then
          /opt/sbin/screen -dmS "iocmon" "$apppath" -noswitch
          sleep 1
          screenreattach iocmon
          exit 0
        else
          clear
          echo -e "${CClear}Executing ${CGreen}IOCMON v$version${CClear} using the SCREEN utility..."
          echo ""
          echo -e "${CClear}IMPORTANT:"
          echo -e "${CClear}In order to keep IOCMON running in the background,"
          echo -e "${CClear}properly exit the SCREEN session by using: ${CGreen}CTRL-A + D${CClear}"
          echo ""
          /opt/sbin/screen -dmS "iocmon" "$apppath" -noswitch
          sleep 5
          screenreattach iocmon
          exit 0
        fi
      else
        if [ "$bypassscreentimer" == "1" ]; then
          sleep 1
        else
          clear
          echo -e "${CClear}Connecting to existing ${CGreen}IOCMON v$version${CClear} SCREEN session...${CClear}"
          echo ""
          echo -e "${CClear}IMPORTANT:${CClear}"
          echo -e "${CClear}In order to keep IOCMON running in the background,${CClear}"
          echo -e "${CClear}properly exit the SCREEN session by using: ${CGreen}CTRL-A + D${CClear}"
          echo ""
          echo -e "${CClear}Switching to the SCREEN session in T-5 sec...${CClear}"
          echo -e "${CClear}"
          spinner 5
        fi
      fi
    screenreattach "$ScreenSess"
    exit 0
fi

# -------------------------------------------------------------------------------------------------------------------------
# Begin IOCMON Main Loop
# -------------------------------------------------------------------------------------------------------------------------

# Refuse to start a second concurrent main loop - two live instances race on every shared state/manifest file.
pidfile="$addonsdir/iocmon.pid"
mkdir -m 755 -p "$addonsdir"
if [ -f "$pidfile" ]; then
  oldpid="$(cat "$pidfile" 2>/dev/null)"
  if [ -n "$oldpid" ] && [ "$oldpid" != "$$" ] && iocmonpid "$oldpid"; then
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - ERROR: Another IOCMON instance (PID $oldpid) is already running - exiting to avoid state corruption." >> "$logfile"
    clear
    echo -e "${CRed}ERROR: IOCMON is already running (PID $oldpid) - a second instance was not started, to avoid two${CClear}"
    echo -e "${CRed}copies corrupting shared detection data.${CClear}"
    echo ""
    echo -e "To view or reattach to the already-running instance, use:"
    echo -e "  ${CGreen}iocmon -screen${CClear}   (or: ${CGreen}sh $apppath -screen${CClear})"
    echo ""
    echo -e "If IOCMON is NOT actually still running, confirm with ${CGreen}ps | grep iocmon${CClear} or ${CGreen}screen -ls${CClear},"
    echo -e "then remove the stale lock file: ${CGreen}rm -f $pidfile${CClear}"
    echo ""
    exit 1
  fi
fi
echo "$$" > "$pidfile"
rm -f "$restartpendingfile" >/dev/null 2>&1
rm -f "$updatingfile" >/dev/null 2>&1
trap 'rm -f "$pidfile"' EXIT; trap 'exit 130' INT; trap 'exit 143' TERM
trap 'winchpending=1' WINCH

# Check for and add/refresh the alias for IOCMON, only touching the file if it's actually missing/stale
[ -f /jffs/configs/profile.add ] || : > /jffs/configs/profile.add
wantedaliasline="alias iocmon=\"sh /jffs/scripts/iocmon.sh -screen -now\" # added by iocmon"
currentaliasline="$(grep '# added by iocmon' /jffs/configs/profile.add 2>/dev/null)"
if [ "$currentaliasline" != "$wantedaliasline" ]; then
  sed -i '/# added by iocmon/d' /jffs/configs/profile.add
  echo "$wantedaliasline" >> /jffs/configs/profile.add
fi

# Grab the IOCMON config file and read it in, or run interactive first-time setup (including drive selection)
if [ -f "$config" ]; then
  . "$config"
  resolvelogfile
  migratefeedkeys
  aghmigrateauth
  if [ -z "$alertlevel" ]; then
    saveconfig
    echo -e "$(date +'%b %d %Y %X') $(_GetLAN_HostName_) IOCMON[$$] - INFO: Alert level set to '$alertlevel', carried over from the earlier 'Feed Matches Only' setting." >> "$logfile"
  fi
else
  initialsetup
fi

checktimeoutbin
webuirefreshpage
migrateiocseverity

# Check for updates
updatecheck
betacheck

# -------------------------------------------------------------------------------------------------------------------------
# renderalertbanner prints the SECURITY ALERT block; called from renderdashboard at the top or the bottom.

renderalertbanner()
{
  echo -e "${InvGreen} ${CClear}"
  pendingcount="$(sed -n '1p' "$stateroot/alert_pending" 2>/dev/null)"
  pendingsummary="$(sed -n '2p' "$stateroot/alert_pending" 2>/dev/null)"
  [ "${#pendingsummary}" -gt 129 ] && pendingsummary="$(printf '%.128s' "$pendingsummary")>"
  echo -en "${InvRed}${CWhite} "; padright "!!! SECURITY ALERT: ${pendingcount:-1} unacknowledged IOC detection(s) !!!" 137; echo -e "${CClear}"
  pendingsummary="$(printf '%s' "$pendingsummary" | sed 's/\\/\\\\/g')"
  echo -e " ${CWhite}Latest: ${pendingsummary:-see the IoC log}${CClear}"
  echo -en "${InvRed}${CWhite} "; padright "Press (A) to Acknowledge" 137; echo -e "${CClear}"
}

# -------------------------------------------------------------------------------------------------------------------------
# collectstatus gathers the plain values the dashboard and the web interface both show; it needs resolvestateroot first

collectstatus()
{
  feedsindicatorcount=0
  feedsbreakdown=""
  feedsoldest="n/a"
  if [ -n "$feedsroot" ] && [ -f "$feedsroot/ips.txt" ]; then
    feedsindicatorcount="$(( $(cat "$feedsroot/ips.txt" "$feedsroot/domains.txt" "$feedsroot/hashes.txt" 2>/dev/null | wc -l | tr -d ' ') + $(qfeedscount) ))"
    feedsbreakdown="$(feedsourcecounts | sed 's/ *$//')"
    feedsoldest="$(feedsoldestfetch)"
  fi

  fsbaselinecount=0
  [ -n "$stateroot" ] && [ -f "$stateroot/fs_baseline.db" ] && fsbaselinecount="$(wc -l < "$stateroot/fs_baseline.db" | tr -d ' ')"

  lastalert="$(lastalertsummary)"
  todaycount="$(alertstoday)"

  cronscheduled=0
  which cru >/dev/null 2>&1 && crul && printf '%s\n' "$cruout" | grep -q "IOCMONFeeds" && cronscheduled=1

  nvramget odmpid
  routermodel="$nvramval"
  [ -z "$routermodel" ] && nvramget productid && routermodel="$nvramval"
  routeruptime="$(uptime 2>/dev/null | sed -E 's/^[^,]*up[[:space:]]*//; s/,[[:space:]]*[0-9]+ users?.*//')"
  drivefreespace="n/a"
  [ -n "$iocmonroot" ] && drivefreespace="$(df -h "$iocmonroot" 2>/dev/null | awk 'NR==2{print $4}')"
  [ -z "$drivefreespace" ] && drivefreespace="n/a"
}

# -------------------------------------------------------------------------------------------------------------------------
# renderdashboard paints the whole dashboard screen from current state; no detection logic of its own.

renderdashboard()
{
  clear

  versionPF=$(printf "%-8s" "$version")

  titlewidth=137
  titleleft=" IOCMON - v${versionPF}"
  titlemid="Security-Intelligence Monitor"
  titleright="$(date) "
  titlemidavail=$((titlewidth - ${#titleleft} - ${#titleright}))
  titlemidpad=$((titlemidavail - ${#titlemid}))
  [ "$titlemidpad" -lt 0 ] && titlemidpad=0
  titlemidpadl=$((titlemidpad / 2))
  titlemidpadr=$((titlemidpad - titlemidpadl))

  echo -en "${InvGreen} "
  echo -e "${InvDkGray}${titleleft}$(printf '%*s' "$titlemidpadl" '')${CWhite}${titlemid}${InvDkGray}$(printf '%*s' "$titlemidpadr" '')${titleright}${CClear}"

  resolvestateroot
  if [ "$alertbanneratbottom" -ne 1 ] && [ -n "$stateroot" ] && [ -f "$stateroot/alert_pending" ]; then
    renderalertbanner
  fi

  if [ "$track" = "0" ] && [ "$UpdateNotify" != "0" ]; then
    echo -e "$UpdateNotify"
  fi
  if [ "$track" = "1" ] && [ "$BUpdateNotify" != "0" ]; then
    echo -e "$BUpdateNotify"
  fi

  echo -e "${InvGreen} ${CClear}"

  collectstatus

  dnsstatus="${CDkGray}off${CClear}"
  dnslogcolor="$CDkGray"
  if [ "$enablednswatch" -eq 1 ]; then
    if dnsusesagh && ! aghanylogin; then dnsstatus="${CYellow}skipped, AdGuard Home login missing${CClear}"; dnslogcolor="$CYellow"
    elif [ "$aghfailover" = "1" ] && dnsusesagh; then dnsstatus="${CYellow}on, AdGuard Home backup${CClear} (${dnsqueriedcount:-0} checked, checked ${dnslastcheck:-n/a})"; dnslogcolor="$CYellow"
    elif [ "$aghfailover" = "2" ] && dnsusesagh; then dnsstatus="${CYellow}AdGuard Home not answering${CClear} (last checked ${dnslastcheck:-n/a})"; dnslogcolor="$CYellow"
    elif dnsusesagh; then dnsstatus="${CGreen}on${CClear} (AdGuard Home, ${dnsqueriedcount:-0} checked, checked ${dnslastcheck:-n/a})"
    elif dnsquerylogenabled; then dnsstatus="${CGreen}on${CClear} (${dnsqueriedcount:-0} queries checked, checked ${dnslastcheck:-n/a})"; else dnsstatus="${CYellow}on, awaiting query-log setup${CClear}"; fi
  fi
  conntrackstatus="${CDkGray}off${CClear}"
  [ "$enableconntrackwatch" -eq 1 ] && conntrackstatus="${CGreen}on${CClear} (${conntrackchecked} dst ips, checked ${conntracklastcheck:-n/a})"
  authstatus="${CDkGray}off${CClear}"
  [ "$enableauthwatch" -eq 1 ] && authstatus="${CGreen}on${CClear} (+${authchecked} new, checked ${authlastcheck:-n/a})"
  nvramstatus="${CDkGray}off${CClear}"
  [ "$enablenvramwatch" -eq 1 ] && nvramstatus="${CGreen}on${CClear} ($(echo "$nvramwatchvars" | wc -w | tr -d ' ') vars watched, checked ${nvramlastcheck:-n/a})"

  fsstatus="${CDkGray}off${CClear}"
  if [ "$enablefsintegrity" -eq 1 ]; then
    if [ -n "$stateroot" ] && [ -f "$stateroot/fs_baseline.db" ]; then
      fsstatus="${CGreen}on${CClear} ($fsbaselinecount files baselined)"
    else
      fsstatus="${CYellow}on, no baseline yet${CClear}"
    fi
  fi

  if [ "$enablealertemail" = "1" ]; then
    amtmdisp="${CGreen}On${CClear}"
  else
    amtmdisp="${CDkGray}Off${CClear}"
  fi
  rldisp="${CGreen}unlimited${CClear}"
  [ "$ratelimit" != "0" ] && rldisp="${CGreen}${ratelimit}/h${CClear}"

  cronstatus="${CDkGray}not scheduled${CClear}"
  [ "$cronscheduled" -eq 1 ] && cronstatus="${CGreen}scheduled${CClear}"

  local lastalertshown="$lastalert" feedsbreakdownshown="$feedsbreakdown"
  [ "${#lastalertshown}" -gt 49 ] && lastalertshown="$(printf '%.48s' "$lastalertshown")>"
  [ "${#feedsbreakdownshown}" -gt 65 ] && feedsbreakdownshown="$(echo "$feedsbreakdownshown" | cut -c1-62)..."
  echo -en "${InvGreen} ${CClear} "; padright "${CWhite}Feeds: ${CGreen}${feedsindicatorcount}${CClear} loaded, every ${CGreen}${feedupdatehrs}h${CClear}, oldest ${CGreen}${feedsoldest}${CClear}" 75; echo -e "${CWhite}Last Alert: ${CGreen}${lastalertshown}${CClear}"
  echo -en "${InvGreen} ${CClear} "; padright "${CWhite}Sources: ${CGreen}${feedsbreakdownshown:-none}${CClear}" 75; echo -e "${CWhite}Alerts Today: ${CGreen}${todaycount}${CClear} | $(reputationstatus $((61 - 17 - ${#todaycount})))"
  echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
  echo -en "${InvGreen} ${CClear} "; padright "${CWhite}conntrack: $conntrackstatus" 75; echo -e "${CWhite}dns: $dnsstatus"
  dnslogline=""
  [ "$enablednswatch" -eq 1 ] && [ -n "$dnslogshort" ] && dnslogline="${dnslogcolor}${dnslogshort}${CClear}"
  echo -en "${InvGreen} ${CClear} "; padright "${CWhite}auth: $authstatus" 75; echo -e "$dnslogline"
  echo -en "${InvGreen} ${CClear} "; padright "${CWhite}nvram: $nvramstatus" 75; echo -e "${CWhite}fs-integrity: $fsstatus"
  echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
  echo -en "${InvGreen} ${CClear} "; padright "${CWhite}Email: $amtmdisp (limit: $rldisp)" 75; echo -e "${CWhite}Cron: $cronstatus"
  echo -en "${InvGreen} ${CClear} "; padright "${CWhite}Router: ${CGreen}${routermodel:-unknown}${CClear} ($(_GetLAN_HostName_))" 75; echo -e "${CWhite}Storage: $drivestatus"
  echo -en "${InvGreen} ${CClear} "; padright "${CDkGray}${routeruptime}${CClear}" 75; echo -e "${CWhite}Drive free: ${CGreen}${drivefreespace}${CClear}"
  echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"

  echo -e "${InvGreen} ${CClear} ${CWhite}Filesystem Integrity${CClear}"
  if [ "$enablefsintegrity" -ne 1 ]; then
    echo -e "${InvGreen} ${CClear}   Disabled."
  elif [ -n "$stateroot" ] && [ -f "$stateroot/fs_scan_summary.txt" ]; then
    while IFS= read -r summaryline; do
      echo -e "${InvGreen} ${CClear}   ${summaryline}"
    done < "$stateroot/fs_scan_summary.txt"
    if [ -s "$stateroot/fs_scan_errors.txt" ]; then
      echo -e "${InvGreen} ${CClear}   ${CRed}$(wc -l < "$stateroot/fs_scan_errors.txt" | tr -d ' ') scan error(s) - first: $(head -n1 "$stateroot/fs_scan_errors.txt")${CClear}"
    fi
  else
    echo -e "${InvGreen} ${CClear}   ${CYellow}No scan has run yet (next check due within ${fsintegrityhrs}h, or press (I) to run one now).${CClear}"
  fi
  echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"

  if [ "$alertviewmode" = "dropbear" ]; then
    echo -e "${InvGreen} ${CClear} ${CWhite}Recent Dropbear Attempts${CClear} (Logs: [${CGreen}V${CClear}] Full, [${CGreen}O${CClear}] IoC Detections, [${CGreen}H${CClear}] Hash, [${CGreen}U${CClear}] Reputation, [${CGreen}R${CClear}] Clear Log)"
    if [ -n "$stateroot" ] && [ -n "$(logtail "$stateroot/dropbear_attempts.log" 1)" ]; then
      logtail "$stateroot/dropbear_attempts.log" 10 | while IFS= read -r dbline; do
        [ "${#dbline}" -gt 134 ] && dbline="$(printf '%.133s' "$dbline")>"
        echo -e "${InvGreen} ${CClear}   ${CYellow}${dbline}${CClear}"
      done
    else
      echo -e "${InvGreen} ${CClear}   ${CDkGray}No dropbear login-failure attempts logged yet.${CClear}"
    fi
  elif [ "$alertviewmode" = "reputation" ]; then
    echo -e "${InvGreen} ${CClear} ${CWhite}Recent Reputation Lookups${CClear} (Logs: [${CGreen}V${CClear}] Full, [${CGreen}O${CClear}] IoC Detections, [${CGreen}D${CClear}] Dropbear, [${CGreen}H${CClear}] Hash, [${CGreen}R${CClear}] Clear Log)"
    if [ -n "$stateroot" ] && [ -n "$(logtail "$stateroot/reputation.log" 1)" ]; then
      logtail "$stateroot/reputation.log" 10 | while IFS= read -r repline; do
        repscore="$(echo "$repline" | cut -d'|' -f3 | sed 's/^ *//; s/ *$//')"
        repcolor="$CDkGray"
        case "$repscore" in
          *%) repscore="${repscore%\%}"; repcolor="$CGreen"
              [ "$repscore" -ge 25 ] 2>/dev/null && repcolor="$CYellow"
              [ "$repscore" -ge 75 ] 2>/dev/null && repcolor="$CRed" ;;
        esac
        [ "${#repline}" -gt 134 ] && repline="$(printf '%.133s' "$repline")>"
        echo -e "${InvGreen} ${CClear}   ${repcolor}${repline}${CClear}"
      done
    elif [ "$enableabuseipdb" -eq 1 ]; then
      echo -e "${InvGreen} ${CClear}   ${CDkGray}No AbuseIPDB reputation lookups yet - one runs each time a conntrack, DNS, dropbear or httpd alert is raised.${CClear}"
    else
      echo -e "${InvGreen} ${CClear}   ${CDkGray}The AbuseIPDB reputation check is off - turn it on under Configuration Menu (2) Feed Sources, Reputation, API Keys and Lookups.${CClear}"
    fi
  elif [ "$alertviewmode" = "hash" ]; then
    echo -e "${InvGreen} ${CClear} ${CWhite}Recent Hash-Check Log${CClear} (Logs: [${CGreen}V${CClear}] Full, [${CGreen}O${CClear}] IoC Detections, [${CGreen}D${CClear}] Dropbear, [${CGreen}U${CClear}] Reputation, [${CGreen}R${CClear}] Clear Log)"
    if [ -n "$stateroot" ] && [ -n "$(logtail "$stateroot/hash_check.log" 1)" ]; then
      logtail "$stateroot/hash_check.log" 10 | while IFS= read -r hashline; do
        [ "${#hashline}" -gt 134 ] && hashline="$(printf '%.133s' "$hashline")>"
        echo -e "${InvGreen} ${CClear}   ${CCyan}${hashline}${CClear}"
      done
    else
      echo -e "${InvGreen} ${CClear}   ${CDkGray}No files have been checked against the malware-hash feed yet.${CClear}"
    fi
  else
    echo -e "${InvGreen} ${CClear} ${CWhite}Recent IoC Detections${CClear} (Press [${CGreen}Z${CClear}] Add DNS Exceptions, Logs: [${CGreen}V${CClear}] Full, [${CGreen}D${CClear}] Dropbear, [${CGreen}H${CClear}] Hash, [${CGreen}U${CClear}] Reputation, [${CGreen}N${CClear}] OTX Rpt, [${CGreen}R${CClear}] Clear Log)"
    if [ -n "$stateroot" ] && [ -n "$(logtail "$stateroot/ioc_alerts.log" 1)" ]; then
      : > "$dnsnummapfile"
      dnsnum=0
      logtail "$stateroot/ioc_alerts.log" 10 | while IFS= read -r iocline; do
        kind="$(echo "$iocline" | cut -d'|' -f2 | sed 's/^ *//; s/ *$//')"
        case "$iocline" in
          *" | sev:critical") ioccolor="$CRed" ;;
          *" | sev:warning") ioccolor="$CYellow" ;;
          *" | sev:info") ioccolor="$CDkGray" ;;
          *) ioccolor="$CGreen" ;;
        esac
        iocline="${iocline% | sev:*}"
        iocline="$(printf '%s' "$iocline" | sed 's/\\/\\\\/g')"
        if [ "$kind" = "dns" ]; then
          dnsnum=$((dnsnum + 1))
          domain="$(echo "$iocline" | cut -d'|' -f3 | sed 's/^ *//; s/ *$//')"
          domain="${domain#*->}"
          printf '%s\t%s\n' "$dnsnum" "$domain" >> "$dnsnummapfile"
          numstr="$dnsnum"; [ "$dnsnum" -eq 10 ] && numstr=0
          [ "${#iocline}" -gt 130 ] && iocline="$(printf '%.129s' "$iocline")>"
          echo -e "${InvGreen} ${CClear}   [${CGreen}${numstr}${CClear}] ${ioccolor}${iocline}${CClear}"
        else
          [ "${#iocline}" -gt 130 ] && iocline="$(printf '%.129s' "$iocline")>"
          echo -e "${InvGreen} ${CClear}   [ ] ${ioccolor}${iocline}${CClear}"
        fi
      done
    else
      echo -e "${InvGreen} ${CClear}   ${CDkGray}No detections logged yet. Press (T) to simulate one and confirm alerting works.${CClear}"
    fi
  fi
  echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
  if [ "$alertbanneratbottom" -eq 1 ] && [ -n "$stateroot" ] && [ -f "$stateroot/alert_pending" ]; then
    renderalertbanner
  fi
  echo ""
  printf '\033[s'
  progressfirstdraw=1
}

while true; do
  clear
  echo -e "${CGreen}IOCMON v$version [Scanning for IoC's ... Please stand by]${CClear}"

  if [ -f "$config" ]; then
    . "$config"
    resolvelogfile
  else
    initialsetup
  fi

  _SetUpTimeoutCmdVars_
  checkscriptreplaced
  rm -f "$abuseipdbcyclefile"

  checkdrivealive
  checkfeedupdate
  checklogrotate

  scanbulletprinted=0

  checkconntrack
  if [ "$enableconntrackwatch" -eq 1 ]; then
    blanklineguard
    echo -e "  ${CGreen}*${CClear} Evaluated ${CGreen}${conntrackchecked}${CClear} active connection(s) against known-malicious IP feeds"
    scanbulletprinted=1
    sleep 1
  fi

  checkdns
  if [ "$enablednswatch" -eq 1 ]; then
    blanklineguard
    dnsselfnote=""
    [ "${dnsselfcount:-0}" -gt 0 ] && dnsselfnote=" (${CGreen}${dnsselfcount}${CClear} router lookup(s) by Kairos/Astraea set aside)"
    if [ "$aghfailover" = "2" ] && dnsusesagh; then
      echo -e "  ${CYellow}* WARNING: DNS watch could not read the primary or the backup AdGuard Home - see the IOCMON log.${CClear}"
    elif [ "$aghfailover" = "1" ] && dnsusesagh; then
      echo -e "  ${CYellow}*${CClear} Checked ${CGreen}${dnsqueriedcount}${CClear} DNS domain lookup(s) from the ${CYellow}backup${CClear} AdGuard Home (${aghurl2%/}) against known-malicious-domain feeds${dnsselfnote}"
    elif dnsusesagh && ! aghanylogin; then
      echo -e "  ${CYellow}* WARNING: DNS watch skipped - the AdGuard Home login is missing. Add it under Configuration Menu ${advsettingsmenunum}.2, item 12.${CClear}"
    elif dnsusesagh; then
      echo -e "  ${CGreen}*${CClear} Checked ${CGreen}${dnsqueriedcount}${CClear} DNS domain lookup(s) from AdGuard Home's query log against known-malicious-domain feeds${dnsselfnote}"
    elif dnsquerylogenabled; then
      echo -e "  ${CGreen}*${CClear} Checked ${CGreen}${dnsqueriedcount}${CClear} DNS domain lookup(s) against known-malicious-domain feeds${dnsselfnote}"
    else
      echo -e "  ${CYellow}*${CClear} DNS watch is on but dnsmasq query logging isn't - see Advanced Settings item 4"
    fi
    scanbulletprinted=1
    sleep 1
  fi

  checkauth
  if [ "$enableauthwatch" -eq 1 ]; then
    blanklineguard
    echo -e "  ${CGreen}*${CClear} Scanned ${CGreen}${authchecked}${CClear} new syslog line(s) for dropbear/httpd brute-force login attempts"
    scanbulletprinted=1
    sleep 1
  fi

  checknvram
  if [ "$enablenvramwatch" -eq 1 ]; then
    blanklineguard
    echo -e "  ${CGreen}*${CClear} Compared ${CGreen}$(echo "$nvramwatchvars" | wc -w | tr -d ' ')${CClear} security-relevant NVRAM variable(s) for unexpected changes"
    scanbulletprinted=1
    sleep 1
  fi

  fsintegritycheck
  if [ "$enablefsintegrity" -eq 1 ] && [ "$fsintegrityranthiscycle" -eq 1 ]; then
    blanklineguard
    echo -e "  ${CGreen}*${CClear} Hashed/scanned ${CGreen}${fsscannedcount}${CClear} local file(s) across ${CGreen}${fsdircount}${CClear} watched directories for unauthorized changes (${CGreen}${fsnewcount}${CClear} new, ${CGreen}${fsmodcount}${CClear} modified, ${CGreen}${fsdelcount}${CClear} deleted, ${CGreen}${fspermcount}${CClear} permission-only)"
    scanbulletprinted=1
    sleep 1
  fi

  flushemailbatch

  [ "$scanbulletprinted" -eq 1 ] && sleep 2

  while [ -f "$updatingfile" ]; do
    clear
    echo -e "${CGreen}[IOCMON is in Maintenance Mode]${CClear}"
    echo ""
    echo -e "Trying again in 30 seconds..."
    echo ""
    spinner 30
  done

  renderdashboard
  webpublish

  timer=0
  winchpending=0
  while [ "$timer" -lt "$timerloop" ]; do
    [ "$timerpaused" -ne 1 ] && timer="$((timer+1))"
    if [ "$winchpending" -eq 1 ]; then
      winchpending=0
      renderdashboard
    fi
    preparebar 46 "|"
    progressbaroverride "$timer" "$timerloop" "" "s" "Standard"
    [ -f "$updatingfile" ] && break
  done

done

exit 0

