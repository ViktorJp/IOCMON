#!/bin/sh
# ============================================================================================================================
# iocmon.sh - Asus-Merlin Firmware Security-Intelligence Monitor
# Version: 0.4.7
# Sibling to BACKUPMON, STUNMON, TAILMON, VPNMON-R3, RTRMON, KILLMON, ECLIPSEMON, WXMON and PWRMON
# Last Updated: 2026-Sep-22
# ============================================================================================================================
#
# Description:
#   Reads syslog and other router-provided logs, watches for filesystem changes, and correlates against public
#   indicator-of-compromise (IoC) feeds to alert the user of possible compromise or malware on the router.
#
# File layout:
#   /jffs/scripts/iocmon.sh                                           : main script - control plane, survives reboot
#   /jffs/addons/iocmon.d/iocmon.cfg                                  : config (flat key=value, sourced)
#   /jffs/addons/iocmon.d/version.txt                                 : stable track version file
#   /jffs/addons/iocmon.d/beta.txt                                    : beta track version file
#   /jffs/addons/iocmon.d/iocmon.log                                  : activity/alert log (nano-viewable, trimmed)
#   /jffs/addons/iocmon.d/updating.txt                                : maintenance-mode lock file
#   /jffs/addons/iocmon.d/feeds-degraded/                             : small JFFS-safe feed cache used only in degraded mode
#   /jffs/addons/iocmon.d/state-degraded/                             : small JFFS-safe alert-dedup state used only in degraded mode
#   /tmp/mnt/<extdrivelabel>/iocmon.d/feeds/ips.txt                   : canonical combined IP/netblock indicator list
#   /tmp/mnt/<extdrivelabel>/iocmon.d/feeds/domains.txt               : canonical combined domain indicator list
#   /tmp/mnt/<extdrivelabel>/iocmon.d/feeds/hashes.txt                : canonical combined file-hash indicator list
#   /tmp/mnt/<extdrivelabel>/iocmon.d/feeds/*.raw                     : per-source raw downloads
#   /tmp/mnt/<extdrivelabel>/iocmon.d/feeds/meta/                     : per-source conditional-GET timestamp markers
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/seen_alerts.db            : "kind|indicator<TAB>epoch" alert dedup records
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/dns_checkpoint            : syslog line-count cursor for checkdns
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/auth_checkpoint           : syslog line-count cursor for checkauth
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/fs_baseline.db            : plain sorted file-path list (no stat - see below)
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/fs_scan_marker            : reference file `find -newer` compares against
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/cron_baseline.db          : last-seen `cru l` output for the cron-diff heuristic
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/fs_last_check             : epoch stamp gating the fsintegrityhrs cadence
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/fs_scan_summary.txt       : human-readable last-scan detail (main screen)
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/fs_scan_errors.txt        : this cycle's find stderr, if any
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/fs_size_baseline.db       : per-file size, for mtime-independent MOD detection
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/fs_last_new.txt           : timestamped log of added filenames, trimmed to $logsize
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/fs_last_modified.txt      : timestamped log of modified filenames
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/fs_last_deleted.txt       : timestamped log of deleted filenames
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/fs_last_permchanged.txt   : timestamped log of permission-only changes
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/ioc_alerts.log            : every real detection ever made, kept indefinitely
#   /tmp/mnt/<extdrivelabel>/iocmon.d/state/alert_pending             : pending-count + latest summary; presence = red banner up
#
# Usage:
#   iocmon.sh                                                         : interactive monitoring display
#   iocmon.sh -setup                                                  : configuration menu (drive/feeds/DNS/advanced settings, uninstall)
#   iocmon.sh -screen [-now]                                          : run the monitoring loop in a background SCREEN session
#   iocmon.sh -email                                                  : send a test email to confirm AMTM notifications are configured
#   iocmon.sh -updatefeeds                                            : cron-callable one-shot IoC feed refresh
#   iocmon.sh -fsintegrity                                            : cron-callable one-shot filesystem-integrity + cron-baseline check
#   iocmon.sh -h | -help                                              : this output
#
# Main-screen hotkeys (in addition to (c)onfig/(f)eeds/(i)ntegrity/(l)ogs/(e)xit):
#   (v) view the permanent state/ioc_alerts.log in nano   (t) simulate a detection from a real, currently loaded
#   (a) acknowledge the persistent red alert banner   (p) pause/resume the countdown timer without triggering a rescan
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
version="0.4.7"                 # current script version
apppath="/jffs/scripts/iocmon.sh"  # this script's own deployed path
addonsdir="/jffs/addons/iocmon.d"  # JFFS-side control/config directory
config="/jffs/addons/iocmon.d/iocmon.cfg"  # persisted key=value config file
dlverpath="/jffs/addons/iocmon.d/version.txt"  # stable-track version file
bverpath="/jffs/addons/iocmon.d/beta.txt"  # beta-track version file
logfile="/jffs/addons/iocmon.d/iocmon.log"  # main activity/alert log
updatingfile="/jffs/addons/iocmon.d/updating.txt"  # maintenance-mode lock file
dropbearlogfile="/jffs/addons/iocmon.d/dropbear_attempts.log"  # raw dropbear auth-failure log

# Repo used for self-update checks.
iocmonrepostable="https://raw.githubusercontent.com/ViktorJp/IOCMON/main"
iocmonrepobeta="https://raw.githubusercontent.com/ViktorJp/IOCMON/develop"

# AMTM Email Notification Variables - shared library reused verbatim from TAILMON/VPNMON-R3
readonly scriptFileName="${0##*/}"  # this script's own filename
readonly scriptFileNTag="${scriptFileName%.*}"  # filename without extension
readonly CEM_LIB_TAG="master"   # branch of the CustomMiscUtils repo to pull the email library from
readonly CEM_LIB_URL="https://raw.githubusercontent.com/Martinski4GitHub/CustomMiscUtils/${CEM_LIB_TAG}/EMail"  # download URL for the shared email library
readonly CUSTOM_EMAIL_LIBDir="/jffs/addons/shared-libs"  # where the shared AMTM email library lives
readonly CUSTOM_EMAIL_LIBName="CustomEMailFunctions.lib.sh"  # shared AMTM email library filename
readonly CUSTOM_EMAIL_LIBFile="${CUSTOM_EMAIL_LIBDir}/$CUSTOM_EMAIL_LIBName"  # full path to the shared email library

# -------------------------------------------------------------------------------------------------------------------------
# Config schema defaults - these are overwritten by $config once it exists

timerloop=60                    # main loop interval, sec
feedupdatehrs=4                 # IoC feed refresh cadence
fsintegrityhrs=6                # filesystem baseline diff cadence (independent of timerloop)

enablethreatfox=0               # enable the ThreatFox feed source
threatfoxapikey=""              # optional - falls back to unauthenticated CSV export if empty
enablespamhaus=1                # enable the Spamhaus DROP/EDROP feed source
enablefeodo=1                   # enable the Feodo Tracker feed source
enableurlhaus=1                 # enable the URLhaus feed source

enablednswatch=0                # tail dnsmasq log for domain matches against feed data - off by default so a fresh install doesn't start "awaiting dnsmasq setup"
dnsexceptions=""                # space-separated domains that match a feed but never alert/email, just an INFO log line - for known false positives
enablednstunnel=0               # behavioral DNS-tunneling/exfiltration heuristic (query volume/name-length patterns, not feed-based) - off by default
dnstunnelsubthreshold=20        # distinct subdomains under one base domain from one source IP, within a single check tick, to flag as possible tunneling
dnstunnelnamelen=60             # a single query name at or above this length (chars) is flagged on its own, regardless of repetition
enableconntrackwatch=1          # poll nf_conntrack for IP matches
enablefwlogwatch=0              # requires an iptables LOG rule; setup menu can add it
enableauthwatch=1               # dropbear/httpd brute-force detection, no feed dependency
authfailthreshold=5             # same-source-IP login failures within ONE check tick to trigger a burst alert
authslowwindowhrs=24            # sliding window, in hours, for the low-and-slow brute-force detector below
authslowthreshold=15            # same-source-IP login failures across that whole window to trigger a sustained alert

enablefsintegrity=1
fswatchdirs="/jffs/scripts /jffs/configs /jffs/addons /tmp/mnt/$extdrivelabel"  # /opt/bin,/opt/sbin,etc. deliberately excluded - already covered via the drive-root watch
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

extdrivelabel=""                # resolved USB label, not the live path - drive resolution lands in a later phase

enablealertemail=1              # send an AMTM email whenever a real IOC detection fires
ratelimit=0                     # max emails/hour, 0 = unlimited
logsize=2000                    # line cap for $logfile and other trimmed log files
autostart=0                     # launch the background monitor via post-mount on boot
schedule=1                      # run IOCMON's own daily self-update check via cron
schedulehrs=4                   # hour of day for the daily self-update check
schedulemin=0                   # minute of hour for the daily self-update check
updateiocm=0                    # autoupdate IOCMON script itself
track=0                         # update track: 0 = stable, 1 = beta

# Well-known Merlin persistent filenames living directly in /jffs/scripts
fsstartupscripts="services-start services-stop firewall-start wan-start wan-event nat-start post-mount unmount init-start dhcpc-event openvpn-event wg-event"

# Security-relevant NVRAM variables checknvram() diffs every main-loop tick
nvramwatchvars="sshd_enable sshd_forwarding sshd_pass sshd_port sshd_port_x sshd_authkeys telnetd_enable wan_dns wan0_dns wan1_dns wan_proto wan0_proto wan1_proto jffs2_scripts dmz_ip vts_enable_x vts_rulelist vts_upnplist autofw_enable_x autofw_rulelist"

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
# Promptyn is a simple function that accepts y/n input

promptyn()
{   # No defaults, just y or n
  while true; do
    read -p "$1" -n 1 -r yn
      case "${yn}" in
        [Yy]* ) return 0 ;;
        [Nn]* ) return 1 ;;
        * ) echo -e "\nPlease answer y or n.";;
      esac
  done
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
    curl --silent --retry 3 "$iocmonrepostable/iocmon.sh" -o "/jffs/scripts/iocmon.sh" && chmod 755 "/jffs/scripts/iocmon.sh"
    DLsuccess=$?
    if [ "$DLsuccess" -eq 0 ]; then
      echo -e "${InvGreen} ${CClear} IOCMON Download/Update Success."
      echo ""
    else
      echo -e "${InvRed} ${CClear} IOCMON Download/Update Failed. Please check all the things."
      echo ""
    fi

    return "$DLsuccess"
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
    [ "${#key_press}" -eq 1 ]
    return $?
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

  if [ "$progresspromptactive" -ne 1 ]; then
    printf "\033[2K\r%b %s\033[2D" "$status_text" "$input_text"
    progresspromptactive=1
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

  [ "$1" -eq 1 ] && progresspromptactive=0

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
      progresspromptactive=0
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
          [Tt]) testdetection;;
          [Aa]) acknowledgealert;;
          [Ll]) vlogs;;
          [Pp]) if [ "$timerpaused" -eq 1 ]; then timerpaused=0; else timerpaused=1; fi; renderdashboard;;
          [Xx]) progresspromptactive=0; renderdashboard; [ -x /opt/sbin/screen ] && /opt/sbin/screen -S iocmon -X detach;;
          [Ee]) logoNMexit; echo -e "${CClear}\n"; exit 0;;
          *) if [ "$timerpaused" -eq 1 ]; then renderdashboard; else timer=$timerloop; fi;;
      esac
  elif [ "$menu_line_submitted" -eq 1 ]; then
      resetinvalidprogressinput
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# booleantoyesno renders a 0/1 config value as Yes/No for menu display

booleantoyesno()
{
  if [ "$1" -eq 1 ]; then
    echo "Yes"
  else
    echo "No"
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# padright prints a (possibly color-coded) string followed by however many spaces bring its VISIBLE width up to $2

padright()
{
  local text="$1" width="$2" esc stripped visiblelen pad
  esc="$(printf '\033')"
  stripped="$(printf '%b' "$text" | sed "s/${esc}\[[0-9;]*m//g")"
  visiblelen=${#stripped}
  pad=$((width - visiblelen))
  [ "$pad" -lt 1 ] && pad=1
  printf '%b' "$text"
  printf '%*s' "$pad" ""
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
# lastalertsummary reads the most recent "IOC match" log line and echoes "HH:MM kind: indicator", or "none yet".

lastalertsummary()
{
  local line
  line="$(grep "WARNING: IOC match" "$logfile" 2>/dev/null | tail -1)"
  if [ -z "$line" ]; then
    echo "none yet"
    return
  fi
  echo "$line" | sed -E 's/^[A-Za-z]+ [0-9]+ [0-9]+ ([0-9:]+) .*IOC match \(([a-z]+)\): ([^ ]+).*/\1 \2: \3/'
}

alertstoday()
{
  grep "$(date +'%b %d %Y')" "$logfile" 2>/dev/null | grep -c "WARNING: IOC match"
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
  curl --silent --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors --fail "$iocmonrepostable/version.txt" -o "$dlverpath"

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
  curl --silent --retry 3 --connect-timeout 3 --max-time 6 --retry-delay 1 --retry-all-errors --fail "$iocmonrepobeta/version.txt" -o "$bverpath"

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
# saveconfig writes the current in-memory config out to iocmon.cfg, then sources it back immediately

saveconfig()
{
  { echo 'timerloop='$timerloop
    echo 'feedupdatehrs='$feedupdatehrs
    echo 'fsintegrityhrs='$fsintegrityhrs

    echo 'enablethreatfox='$enablethreatfox
    echo 'threatfoxapikey="'"$threatfoxapikey"'"'
    echo 'enablespamhaus='$enablespamhaus
    echo 'enablefeodo='$enablefeodo
    echo 'enableurlhaus='$enableurlhaus

    echo 'enablednswatch='$enablednswatch
    echo 'dnsexceptions="'"$dnsexceptions"'"'
    echo 'enablednstunnel='$enablednstunnel
    echo 'dnstunnelsubthreshold='$dnstunnelsubthreshold
    echo 'dnstunnelnamelen='$dnstunnelnamelen
    echo 'enableconntrackwatch='$enableconntrackwatch
    echo 'enablefwlogwatch='$enablefwlogwatch
    echo 'enableauthwatch='$enableauthwatch
    echo 'authfailthreshold='$authfailthreshold
    echo 'authslowwindowhrs='$authslowwindowhrs
    echo 'authslowthreshold='$authslowthreshold

    echo 'enablefsintegrity='$enablefsintegrity
    echo 'fswatchdirs="'"$fswatchdirs"'"'
    echo 'fswatchexclude="'"$fswatchexclude"'"'
    echo 'fsexcludeext="'"$fsexcludeext"'"'
    echo 'fsexcludefiles="'"$fsexcludefiles"'"'
    echo 'fsmaxhashsize='$fsmaxhashsize
    echo 'enablequarantine='$enablequarantine
    echo 'enablecrondiff='$enablecrondiff
    echo 'cronexceptions="'"$cronexceptions"'"'
    echo 'enablenvramwatch='$enablenvramwatch
    echo 'enablefwrulediff='$enablefwrulediff
    echo 'enablefsdeletionwatch='$enablefsdeletionwatch
    echo 'enablepermwatch='$enablepermwatch

    echo 'extdrivelabel="'"$extdrivelabel"'"'

    echo 'enablealertemail='$enablealertemail
    echo 'ratelimit='$ratelimit
    echo 'logsize='$logsize
    echo 'autostart='$autostart
    echo 'schedule='$schedule
    echo 'schedulehrs='$schedulehrs
    echo 'schedulemin='$schedulemin
    echo 'updateiocm='$updateiocm
    echo 'track='$track
  } > "$config"

  echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - INFO: IOCMON config has been updated." >> "$logfile"

  if [ -f "$config" ]; then
    . "$config"
  fi

  schedulecron
  autostart
}

# -------------------------------------------------------------------------------------------------------------------------
# getdrivelabel resolves the USB label for a given mount point

getdrivelabel()
{
  local mp="$1" devsd devnode lbl=""

  devsd="$(awk -v mp="$mp" '$2==mp && $1 ~ /^\/dev\/sd/ {print $1; exit}' /proc/mounts)"
  devnode="${devsd##*/}"

  if [ -n "$devnode" ]; then
    lbl="$(nvram get "usb_path_${devnode}_label" 2>/dev/null)"
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
  clear
  echo -e "${InvGreen} ${InvDkGray}${CWhite} IOCMON External Drive Selection                                                                                                         ${CClear}"
  echo -e "${InvGreen} ${CClear}"
  echo -e "${InvGreen} ${CClear} IOCMON stores IoC feed data and detection state on an external USB drive to avoid${CClear}"
  echo -e "${InvGreen} ${CClear} wearing out the router's internal flash storage. Small control files stay on JFFS.${CClear}"
  echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
  echo ""

  mountpointpaths="$(awk '$1 ~ /^\/dev\/sd/ && $2 ~ /^\/tmp\/mnt\// {print $2}' /proc/mounts | sort -u)"

  if [ -z "$mountpointpaths" ]; then
    echo -e "${CRed}ERROR: No external USB drive was found mounted on this router.${CClear}"
    echo ""
    echo -e "IOCMON can still run in a ${CYellow}degraded JFFS-only mode${CClear}: small feed subsets only (e.g. Feodo's"
    echo -e "recommended list), no hash feeds, and no filesystem-integrity baseline."
    echo ""
    echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - ERROR: No external USB drive found. Degraded JFFS-only mode offered." >> "$logfile"
    echo -e "Continue in degraded JFFS-only mode?"
    if promptyn "[y/n]: "; then
      extdrivelabel=""
      resolveiocmonroot
      saveconfig
      echo ""
      echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - WARNING: Running in degraded JFFS-only mode (no external drive configured)." >> "$logfile"
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
  saveconfig

  echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - INFO: External drive selected: label=$extdrivelabel path=$selecteddrivepath" >> "$logfile"

  echo ""
  echo -e "${CGreen}IOCMON will use: $iocmonroot${CClear}"
  echo ""
  read -rsp $'Press any key to continue...\n' -n1 key
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
      echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - ERROR: Configured external drive (label=$extdrivelabel) is not mounted. Feed/hash operations paused." >> "$logfile"
      driveunmountedalerted=1
    fi
  else
    driveavailable=1
    drivestatus="${CGreen}$iocmonroot${CClear}"
    driveunmountedalerted=0
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# initialsetup creates the addons folder, runs the interactive drive picker, then persists the default config.

initialsetup()
{
  mkdir -m 755 -p "$addonsdir"

  if ! selectextdrive; then
    echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - ERROR: Initial setup did not complete - external drive selection was cancelled." >> "$logfile"
    logoNMexit
    exit 1
  fi

  fswatchdirs="/jffs/scripts /jffs/configs /jffs/addons /tmp/mnt/$extdrivelabel"
  saveconfig

  echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - INFO: IOCMON initial config created with defaults." >> "$logfile"
}

# -------------------------------------------------------------------------------------------------------------------------
# vsetup is the top-level Configuration Menu: a status summary plus hotkeys into each submenu.

vsetup()
{
  while true; do
    clear
    resolveiocmonroot
    echo -e "${InvGreen} ${InvDkGray}${CWhite} IOCMON Configuration Menu                                                                                                               ${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Please choose from the various options below, which allow you to configure IOCMON's${CClear}"
    echo -e "${InvGreen} ${CClear} storage, feed sources, and detection settings, or perform maintenance actions.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(1)${CClear} : Select Feed Storage Location (Ext. Drive)${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(2)${CClear} : Select Feed Sources & API Keys${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(3)${CClear} : Force IoC Threat Feed Refresh${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(4)${CClear} : Force Filesystem-Integrity Scan${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(5)${CClear} : Reset IOCMON back to Default Settings${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(6)${CClear} : Update IOCMON to Latest Version${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(7)${CClear} : Optional Entware Components${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(8)${CClear} : Advanced Settings${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(9)${CClear} : Uninstall IOCMON${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite} | ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(e)${CClear} : Exit${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (1-9, e=Exit): " selsetup
    case "$selsetup" in
      1) selectextdrive ;;
      2) vfeedsources ;;
      3) forcefeeds ;;
      4) forcefsintegrity ;;
      5) vresetdefaults ;;
      6) vupdate ;;
      7) ventwarecomponents ;;
      8) vadvanced ;;
      9) vuninstall ;;
      [Ee]) break ;;
      *) ;;
    esac
  done

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
# veditlist is a numbered add/edit/delete editor for a space-separated list stored in $1

veditlist()
{
  local varname="$1" title="$2" hint="${3:-absolute path}" list count entry idx sel newval delnum newlist overlapmsg

  while true; do
    eval "list=\"\$$varname\""
    clear
    echo -en "${InvGreen} ${InvDkGray}${CWhite} "; padright "$title" 136; echo -e "${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Choose an entry number to edit it, (a) to add a new entry, or (d) to delete one.${CClear}"
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
          fi
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
      *)
        if echo "$sel" | grep -qE '^[0-9]+$' && [ "$sel" -ge 1 ] && [ "$sel" -le "$count" ]; then
          set -- $list
          eval "entry=\"\${$sel}\""
          echo -e "Current: ${CGreen}${entry}${CClear}"
          read -p "New value (blank to keep current): " newval
          if [ -n "$newval" ]; then
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
  cru l 2>/dev/null

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
    clear
    echo -e "${InvGreen} ${InvDkGray}${CWhite} Cron Exceptions                                                                                                                          ${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Cron entries listed below never raise an alert, even when checkcronbaseline/checkentwarecron${CClear}"
    echo -e "${InvGreen} ${CClear} see them disappear and reappear - for entries a script/addon manages on its own schedule.${CClear}"
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
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(d)${CClear} : Delete an exception${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(e)${CClear} : Return to Advanced Settings${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (a=Add, d=Delete, e=Exit): " sel

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
            echo -e "${CGreen}Exception added.${CClear}"
            sleep 1
          fi
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
      *) ;;
    esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# vadvanced is the top-level Advanced Settings menu

vadvanced()
{
  while true; do
    clear
    echo -e "${InvGreen} ${InvDkGray}${CWhite} Advanced Settings                                                                                                                       ${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Please choose from the various options below, which allow you to modify certain${CClear}"
    echo -e "${InvGreen} ${CClear} customizable parameters that affect the operation of this script.${CClear}"
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
      *) ;;
    esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# vadvancedalerting: AMTM email dispatch settings.

vadvancedalerting()
{
  while true; do
    clear
    echo -e "${InvGreen} ${InvDkGray}${CWhite} Advanced Settings - Alerting & Notifications                                                                                            ${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Controls whether and how often IOCMON emails you when a real detection fires.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(1)${CClear} : "; padright "Send an AMTM email whenever a real IOC detection fires" 68; echo -e ": $(booleantoyesno "$enablealertemail")"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(2)${CClear} : "; padright "Maximum alert emails per hour (0 = unlimited)" 68; echo -e ": ${CGreen}$ratelimit${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite} | ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(e)${CClear} : Return to Advanced Settings${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (1-2, e=Exit): " sel
    case "$sel" in
      1) togglesetting enablealertemail ;;
      2) echo -e "Current: ${CGreen}${ratelimit}${CClear}"
         read -p "New email rate limit, emails/hr (0=unlimited, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 0 && ratelimit="$val" && saveconfig; } ;;
      [Ee]) break ;;
      *) ;;
    esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# vadvanceddns: feed-based DNS matching (checkdns) plus the behavioral DNS-tunneling/exfiltration heuristic.

vadvanceddns()
{
  while true; do
    clear
    echo -e "${InvGreen} ${InvDkGray}${CWhite} Advanced Settings - DNS Watch & Tunneling Detection                                                                                     ${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Controls matching DNS lookups against known-malicious-domain feeds, exceptions to${CClear}"
    echo -e "${InvGreen} ${CClear} that matching, and the separate behavioral heuristic for tunneling/exfiltration.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    dnswatchdisp="$(booleantoyesno "$enablednswatch")"
    if [ "$enablednswatch" -eq 1 ] && ! dnsquerylogenabled; then dnswatchdisp="${dnswatchdisp} (awaiting dnsmasq query-log setup)"; fi
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(1)${CClear} : "; padright "Watch DNS lookups for known-malicious domains" 68; echo -e ": $dnswatchdisp"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(2)${CClear} : "; padright "DNS domain exceptions (logged, never alerted/emailed)" 68; echo -e ": ${CGreen}$(echo "$dnsexceptions" | wc -w | tr -d ' ')${CClear} configured"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(3)${CClear} : "; padright "Watch for DNS-tunneling/exfiltration patterns (behavioral, no feed)" 68; echo -e ": $(booleantoyesno "$enablednstunnel")"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(4)${CClear} : "; padright "  Distinct subdomains/tick under one domain to flag as tunneling" 68; echo -e ": ${CGreen}$dnstunnelsubthreshold${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(5)${CClear} : "; padright "  Single query-name length (chars) to flag on its own" 68; echo -e ": ${CGreen}$dnstunnelnamelen${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite} | ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(e)${CClear} : Return to Advanced Settings${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (1-5, e=Exit): " sel
    case "$sel" in
      1) if [ "$enablednswatch" -eq 1 ]; then
           togglesetting enablednswatch
         else
           enablednswatch=1
           saveconfig
           if ! dnsquerylogenabled; then
             echo ""
             echo -e "DNS watching also needs the router's own dnsmasq query logging turned on - IOCMON can't"
             echo -e "see queries dnsmasq isn't logging in the first place."
             echo -e "This appends '${CGreen}log-queries${CClear}' to /jffs/configs/dnsmasq.conf.add and restarts dnsmasq."
             echo -e "Enable DNS query logging now?"
             if promptyn "[y/n]: "; then
               enablednsquerylogging
             fi
             echo ""
             read -rsp $'Press any key to continue...\n' -n1 key
           fi
         fi
         ;;
      2) veditlist dnsexceptions "DNS Domain Exceptions" ;;
      3) togglesetting enablednstunnel ;;
      4) echo -e "Current: ${CGreen}${dnstunnelsubthreshold}${CClear}"
         read -p "New distinct-subdomain threshold (>=1, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 1 && dnstunnelsubthreshold="$val" && saveconfig; } ;;
      5) echo -e "Current: ${CGreen}${dnstunnelnamelen}${CClear}"
         read -p "New query-name length threshold, chars (>=1, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 1 && dnstunnelnamelen="$val" && saveconfig; } ;;
      [Ee]) break ;;
      *) ;;
    esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# vadvancedbruteforce: dropbear/httpd login-failure detection - the per-tick burst check and sliding-window sustained check.

vadvancedbruteforce()
{
  while true; do
    clear
    echo -e "${InvGreen} ${InvDkGray}${CWhite} Advanced Settings - Brute-Force Login Detection                                                                                         ${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Controls dropbear/httpd login-failure detection: an immediate burst check, and a${CClear}"
    echo -e "${InvGreen} ${CClear} separate sliding-window check for a slow, sustained attempt that stays under it.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(1)${CClear} : "; padright "Watch router logins for brute-force (repeated failed) attempts" 68; echo -e ": $(booleantoyesno "$enableauthwatch")"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(2)${CClear} : "; padright "  Same-IP login failures within one check to trigger a burst alert" 68; echo -e ": ${CGreen}$authfailthreshold${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(3)${CClear} : "; padright "  Sliding window (hours) for sustained low-and-slow brute-force" 68; echo -e ": ${CGreen}$authslowwindowhrs${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(4)${CClear} : "; padright "  Same-IP login failures across that window to trigger an alert" 68; echo -e ": ${CGreen}$authslowthreshold${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite} | ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(e)${CClear} : Return to Advanced Settings${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (1-4, e=Exit): " sel
    case "$sel" in
      1) togglesetting enableauthwatch ;;
      2) echo -e "Current: ${CGreen}${authfailthreshold}${CClear}"
         read -p "New burst threshold, failures/tick (>=1, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 1 && authfailthreshold="$val" && saveconfig; } ;;
      3) echo -e "Current: ${CGreen}${authslowwindowhrs}${CClear}"
         read -p "New sliding-window size in hours (>=1, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 1 && authslowwindowhrs="$val" && saveconfig; } ;;
      4) echo -e "Current: ${CGreen}${authslowthreshold}${CClear}"
         read -p "New sustained-window threshold, failures/window (>=1, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 1 && authslowthreshold="$val" && saveconfig; } ;;
      [Ee]) break ;;
      *) ;;
    esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# vadvancedfilesystem: the poll-based baseline diff, watched/excluded paths, hashing/quarantine, and the cron-tampering diff.

vadvancedfilesystem()
{
  while true; do
    clear
    echo -e "${InvGreen} ${InvDkGray}${CWhite} Advanced Settings - Filesystem Integrity & Cron Watch                                                                                   ${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Controls the periodic filesystem baseline scan, what it watches/skips/hashes, what${CClear}"
    echo -e "${InvGreen} ${CClear} it does with a confirmed malware-hash match, and unexpected new cron entries.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 1)${CClear} : "; padright "How often to scan watched folders for file changes, in hours" 68; echo -e ": ${CGreen}$fsintegrityhrs${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 2)${CClear} : "; padright "Watch files/folders below for unexpected changes" 68; echo -e ": $(booleantoyesno "$enablefsintegrity")"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 3)${CClear} : "; padright "Folders to watch for file changes" 68; echo -e ": ${CGreen}$(echo "$fswatchdirs" | wc -w | tr -d ' ')${CClear} configured"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 4)${CClear} : "; padright "Folder NAMES to exclude by name, not by path" 68; echo -e ": ${CGreen}$(echo "$fswatchexclude" | wc -w | tr -d ' ')${CClear} configured"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 5)${CClear} : "; padright "File extensions excluded from every check (new/mod/del/perm)" 68; echo -e ": ${CGreen}$(echo "$fsexcludeext" | wc -w | tr -d ' ')${CClear} configured"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 6)${CClear} : "; padright "Individual files excluded by absolute path" 68; echo -e ": ${CGreen}$(echo "$fsexcludefiles" | wc -w | tr -d ' ')${CClear} configured"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 7)${CClear} : "; padright "Skip hashing files larger than this, in bytes" 68; echo -e ": ${CGreen}$fsmaxhashsize${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 8)${CClear} : "; padright "Auto-quarantine files matching a known-malware hash (strips +x," 68; echo -e ": $(booleantoyesno "$enablequarantine")"
    echo -e "${InvGreen} ${CClear}         renames to <file>.iocmon-quarantine, never deletes)"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 9)${CClear} : "; padright "Alert when a file is DELETED from a critical path" 68; echo -e ": $(booleantoyesno "$enablefsdeletionwatch")"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(10)${CClear} : "; padright "Alert when WRITE/EXECUTE permission is added with no changes" 68; echo -e ": $(booleantoyesno "$enablepermwatch")"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(11)${CClear} : "; padright "Alert on unexpected new scheduled tasks (cru/Entware cron)" 68; echo -e ": $(booleantoyesno "$enablecrondiff")"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(12)${CClear} : "; padright "Cron entries excepted from unexpected-new-entry alerts" 68; echo -e ": ${CGreen}$([ -z "$cronexceptions" ] && echo 0 || printf '%s\n' "$cronexceptions" | wc -l | tr -d ' ')${CClear} configured"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite} | ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(e)${CClear} : Return to Advanced Settings${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (1-12, e=Exit): " sel
    case "$sel" in
      1) echo -e "Current: ${CGreen}${fsintegrityhrs}${CClear}"
         read -p "New filesystem-integrity scan interval in hours (>=1, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 1 && fsintegrityhrs="$val" && saveconfig; } ;;
      2) togglesetting enablefsintegrity ;;
      3) veditlist fswatchdirs "Watched Folders" "absolute path, e.g. /jffs/scripts" ;;
      4) veditlist fswatchexclude "Excluded Folder Names" "a folder NAME, not a path - matches this name anywhere under a watched folder, e.g. Backups" ;;
      5) veditlist fsexcludeext "Excluded File Extensions" "a file extension, e.g. .log (leading dot optional)" ;;
      6) veditlist fsexcludefiles "Excluded Individual Files" "a complete absolute file path, e.g. /jffs/scripts/sample.sh" ;;
      7) echo -e "Current: ${CGreen}${fsmaxhashsize}${CClear}"
         read -p "New max hash size in bytes (>=1, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 1 && fsmaxhashsize="$val" && saveconfig; } ;;
      8) togglesetting enablequarantine ;;
      9) togglesetting enablefsdeletionwatch ;;
      10) togglesetting enablepermwatch ;;
      11) togglesetting enablecrondiff ;;
      12) vcronexceptions ;;
      [Ee]) break ;;
      *) ;;
    esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# vadvancednetwork: the router/network-level watches - conntrack (live traffic) and NVRAM (SSH/Telnet exposure, WAN DNS).

vadvancednetwork()
{
  while true; do
    clear
    echo -e "${InvGreen} ${InvDkGray}${CWhite} Advanced Settings - Network & System Watches                                                                                            ${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Controls watching active connections against known-malicious IPs, watching a short${CClear}"
    echo -e "${InvGreen} ${CClear} list of security-relevant router config state, and unexpected new WAN-exposure rules.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(1)${CClear} : "; padright "Watch active connections for traffic to known-malicious IPs" 68; echo -e ": $(booleantoyesno "$enableconntrackwatch")"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(2)${CClear} : "; padright "Watch security-relevant NVRAM vars (SSH/Telnet, WAN DNS, JFFS)" 68; echo -e ": $(booleantoyesno "$enablenvramwatch")"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(3)${CClear} : "; padright "Alert on new port-forward/DMZ/UPnP rules exposing LAN to WAN" 68; echo -e ": $(booleantoyesno "$enablefwrulediff")"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite} | ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(e)${CClear} : Return to Advanced Settings${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (1-3, e=Exit): " sel
    case "$sel" in
      1) togglesetting enableconntrackwatch ;;
      2) togglesetting enablenvramwatch ;;
      3) togglesetting enablefwrulediff ;;
      [Ee]) break ;;
      *) ;;
    esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# vadvancedgeneral: everything about how the script itself runs/schedules/updates

vadvancedgeneral()
{
  while true; do
    clear
    echo -e "${InvGreen} ${InvDkGray}${CWhite} Advanced Settings - General / Script Behavior                                                                                           ${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Controls the main loop's own cadence, log size, autostart, and IOCMON's self-update${CClear}"
    echo -e "${InvGreen} ${CClear} schedule/track - not specific to any one detection watch.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(1)${CClear} : "; padright "Main loop / detection refresh interval, in seconds" 68; echo -e ": ${CGreen}$timerloop${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(2)${CClear} : "; padright "Maximum rows kept in the activity log (0 = unlimited)" 68; echo -e ": ${CGreen}$logsize${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(3)${CClear} : "; padright "Launch IOCMON automatically in the background after a reboot" 68; echo -e ": $(booleantoyesno "$autostart")"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(4)${CClear} : "; padright "Check for IOCMON script updates on a daily schedule" 68; echo -e ": $(booleantoyesno "$schedule")"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(5)${CClear} : "; padright "  Time of day for that update check (24-hour clock)" 68; echo -e ": ${CGreen}$(printf '%02d' "$schedulehrs"):$(printf '%02d' "$schedulemin")${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(6)${CClear} : "; padright "Automatically install IOCMON script updates when found" 68; echo -e ": $(booleantoyesno "$updateiocm")"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(7)${CClear} : "; padright "Update track: Stable (No) or Beta (Yes)" 68; echo -e ": $(booleantoyesno "$track")"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite} | ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(e)${CClear} : Return to Advanced Settings${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (1-7, e=Exit): " sel
    case "$sel" in
      1) echo -e "Current: ${CGreen}${timerloop}${CClear}"
         read -p "New main loop interval in seconds (>=5, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 5 && timerloop="$val" && saveconfig; } ;;
      2) echo -e "Current: ${CGreen}${logsize}${CClear}"
         read -p "New log size, rows (0=unlimited, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 0 && logsize="$val" && saveconfig; } ;;
      3) togglesetting autostart ;;
      4) togglesetting schedule ;;
      5) echo -e "Current: ${CGreen}$(printf '%02d' "$schedulehrs"):$(printf '%02d' "$schedulemin")${CClear}"
         read -p "New self-update hour (0-23, blank to keep current): " newhr
         read -p "New self-update minute (0-59, blank to keep current): " newmin
         [ -z "$newhr" ] && newhr="$schedulehrs"
         [ -z "$newmin" ] && newmin="$schedulemin"
         if validateint "$newhr" 0 && [ "$newhr" -le 23 ] && validateint "$newmin" 0 && [ "$newmin" -le 59 ]; then
           schedulehrs="$newhr"; schedulemin="$newmin"; saveconfig
         fi
         ;;
      6) togglesetting updateiocm ;;
      7) togglesetting track ;;
      [Ee]) break ;;
      *) ;;
    esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# vfeedsources is the Feed Sources & API Keys submenu: per-source toggles and the optional ThreatFox API key.

vfeedsources()
{
  while true; do
    clear
    echo -e "${InvGreen} ${InvDkGray}${CWhite} Feed Sources & API Keys                                                                                                                 ${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Please choose from the various options below to toggle an IoC feed source on or off,${CClear}"
    echo -e "${InvGreen} ${CClear} or to set the optional ThreatFox API key (blank uses ThreatFox's free CSV export).${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    apikeydisp="<none - using free CSV export>"
    [ -n "$threatfoxapikey" ] && apikeydisp="<set>"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(1)${CClear} : "; padright "Feodo Tracker" 30; echo -e ": $(booleantoyesno "$enablefeodo")"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(2)${CClear} : "; padright "Spamhaus DROP/EDROP" 30; echo -e ": $(booleantoyesno "$enablespamhaus")"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(3)${CClear} : "; padright "URLhaus" 30; echo -e ": $(booleantoyesno "$enableurlhaus")"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(4)${CClear} : "; padright "ThreatFox" 30; echo -e ": $(booleantoyesno "$enablethreatfox")"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(5)${CClear} : "; padright "ThreatFox API Key" 30; echo -e ": ${CGreen}${apikeydisp}${CClear}"
    echo -en "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(6)${CClear} : "; padright "Feed refresh interval (hours)" 30; echo -e ": ${CGreen}$feedupdatehrs${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite} | ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(e)${CClear} : Exit${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (1-6, e=Exit): " selfeed
    case "$selfeed" in
      1) if [ "$enablefeodo" -eq 1 ]; then enablefeodo=0; else enablefeodo=1; fi; saveconfig ;;
      2) if [ "$enablespamhaus" -eq 1 ]; then enablespamhaus=0; else enablespamhaus=1; fi; saveconfig ;;
      3) if [ "$enableurlhaus" -eq 1 ]; then enableurlhaus=0; else enableurlhaus=1; fi; saveconfig ;;
      4) if [ "$enablethreatfox" -eq 1 ]; then enablethreatfox=0; else enablethreatfox=1; fi; saveconfig ;;
      5) read -p "Enter ThreatFox API key (blank to clear): " threatfoxapikey; saveconfig ;;
      6) echo -e "Current: ${CGreen}${feedupdatehrs}${CClear}"
         read -p "New feed refresh interval in hours (>=1, blank to keep current): " val
         [ -n "$val" ] && { validateint "$val" 1 && feedupdatehrs="$val" && saveconfig; } ;;
      [Ee]) break ;;
      *) ;;
    esac
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# vlogs opens the log in nano, then trims it back down to the configured row count

vlogs()
{
  if [ ! -f "$logfile" ]; then
    touch "$logfile"
  fi
  export TERM=linux
  nano +999999 --linenumbers "$logfile"
  trimlogs
  renderdashboard
}

trimlogs()
{
  if [ "$logsize" -gt 0 ]; then
    currlogsize="$(wc -l "$logfile" | awk '{ print $1 }')"

    if [ "$currlogsize" -gt "$logsize" ]; then
      tail -"$logsize" "$logfile" > "${logfile}.tmp"
      mv "${logfile}.tmp" "$logfile"
      echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - INFO: Trimmed the log file down to $logsize lines" >> "$logfile"
    fi
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# trimlogfile is trimlogs' trim-to-N-lines logic generalized to any file/size pair, with no INFO log line of its own.

trimlogfile()
{
  local file="$1" maxlines="$2" curr

  [ "$maxlines" -gt 0 ] || return
  [ -f "$file" ] || return

  curr="$(wc -l < "$file" | tr -d ' ')"
  if [ "$curr" -gt "$maxlines" ]; then
    tail -"$maxlines" "$file" > "${file}.tmp"
    mv "${file}.tmp" "$file"
  fi
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
    curl --silent --show-error --retry 2 --connect-timeout 5 --max-time 30 -z "$metafile" -o "$tmpfile" "$url"
  else
    curl --silent --show-error --retry 2 --connect-timeout 5 --max-time 30 -o "$tmpfile" "$url"
  fi
  curlrc=$?

  if [ "$curlrc" -ne 0 ]; then
    echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - ERROR: Unable to download $name feed ($url) - curl exit $curlrc." >> "$logfile"
    rm -f "$tmpfile"
    return 1
  fi

  if [ ! -s "$tmpfile" ]; then
    rm -f "$tmpfile"
    if [ -s "$rawfile" ]; then
      touch "$metafile"
      return 0
    else
      echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - ERROR: $name feed returned no content and no prior cache exists." >> "$logfile"
      return 1
    fi
  fi

  mv "$tmpfile" "$rawfile"
  touch "$metafile"
  echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - INFO: $name feed updated ($(wc -l < "$rawfile" | tr -d ' ') lines)." >> "$logfile"
  return 0
}

# -------------------------------------------------------------------------------------------------------------------------
# fetchthreatfox has two transports fetchfeedsource can't handle: authenticated JSON (key + jq) or free CSV export.

fetchthreatfox()
{
  local rawfile="$feedsroot/threatfox.raw" metafile="$feedsroot/meta/threatfox.meta"
  local modefile="$feedsroot/meta/threatfox.mode" tmpfile="$rawfile.tmp" curlrc mode

  if [ -n "$threatfoxapikey" ] && which jq >/dev/null 2>&1; then
    mode="api"
    curl --silent --show-error --retry 2 --connect-timeout 5 --max-time 30 \
      -H "Auth-Key: $threatfoxapikey" -H "Content-Type: application/json" \
      -d '{"query":"get_iocs","days":3}' \
      -o "$tmpfile" "https://threatfox-api.abuse.ch/api/v1/"
    curlrc=$?
  else
    mode="csv"
    if [ -f "$metafile" ]; then
      curl --silent --show-error --retry 2 --connect-timeout 5 --max-time 30 -z "$metafile" -o "$tmpfile" "https://threatfox.abuse.ch/export/csv/recent/"
    else
      curl --silent --show-error --retry 2 --connect-timeout 5 --max-time 30 -o "$tmpfile" "https://threatfox.abuse.ch/export/csv/recent/"
    fi
    curlrc=$?
  fi

  if [ "$curlrc" -ne 0 ]; then
    echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - ERROR: Unable to download ThreatFox feed ($mode mode) - curl exit $curlrc." >> "$logfile"
    rm -f "$tmpfile"
    return 1
  fi

  if [ ! -s "$tmpfile" ]; then
    rm -f "$tmpfile"
    if [ -s "$rawfile" ]; then
      touch "$metafile"
      return 0
    else
      echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - ERROR: ThreatFox feed returned no content and no prior cache exists." >> "$logfile"
      return 1
    fi
  fi

  if [ "$mode" = "api" ] && ! grep -q '"query_status"[[:space:]]*:[[:space:]]*"ok"' "$tmpfile"; then
    echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - ERROR: ThreatFox API returned an unexpected response (bad key or rate limit)." >> "$logfile"
    rm -f "$tmpfile"
    return 1
  fi

  mv "$tmpfile" "$rawfile"
  echo "$mode" > "$modefile"
  touch "$metafile"
  echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - INFO: ThreatFox feed updated ($mode mode)." >> "$logfile"
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
# normalizefeeds is the normalize-swap part of the pipeline

normalizefeeds()
{
  local tmpips="$feedsroot/ips.txt.tmp" tmpdomains="$feedsroot/domains.txt.tmp" tmphashes="$feedsroot/hashes.txt.tmp"

  : > "$tmpips"
  : > "$tmpdomains"
  : > "$tmphashes"

  if [ -s "$feedsroot/feodo.raw" ]; then
    awk '!/^#/ && NF {print $1"|feodo|botnet-c2"}' "$feedsroot/feodo.raw" >> "$tmpips"
  fi

  if [ "$feedsdegraded" -eq 0 ]; then
    if [ -s "$feedsroot/spamhaus_drop.raw" ]; then
      awk '!/^;/ && NF {print $1"|spamhaus-drop|netblock"}' "$feedsroot/spamhaus_drop.raw" >> "$tmpips"
    fi
    if [ -s "$feedsroot/spamhaus_edrop.raw" ]; then
      awk '!/^;/ && NF {print $1"|spamhaus-edrop|netblock"}' "$feedsroot/spamhaus_edrop.raw" >> "$tmpips"
    fi

    if [ -s "$feedsroot/urlhaus.raw" ]; then
      awk '!/^#/ && NF>=2 {print $2"|urlhaus|malware-distribution"}' "$feedsroot/urlhaus.raw" >> "$tmpdomains"
    fi

    if [ -s "$feedsroot/threatfox.raw" ]; then
      local tfmode="csv"
      [ -f "$feedsroot/meta/threatfox.mode" ] && tfmode="$(cat "$feedsroot/meta/threatfox.mode" 2>/dev/null)"

      if [ "$tfmode" = "api" ] && which jq >/dev/null 2>&1; then
        jq -r 'if .query_status=="ok" then (.data[]? | [(.ioc // ""), (.ioc_type // ""), (.malware_printable // ""), (.confidence_level // "")] | @tsv) else empty end' "$feedsroot/threatfox.raw" 2>/dev/null | \
          awk -F'\t' -v ipsout="$tmpips" -v domainsout="$tmpdomains" -v hashesout="$tmphashes" '
            {
              val=$1; typ=$2; mal=$3; conf=$4
              if (val=="" || typ=="") next
              if (mal != "") { fam = (conf != "") ? mal" (confidence: "conf")" : mal } else { fam = "" }
              if (typ=="ip:port") { sub(/:[0-9]+$/,"",val); if (fam=="") fam="ip"; print val"|threatfox|"fam >> ipsout }
              else if (typ=="domain") { if (fam=="") fam="domain"; print val"|threatfox|"fam >> domainsout }
              else if (typ=="url") {
                host=val
                sub(/^[A-Za-z]+:\/\//,"",host)
                sub(/[\/:?].*$/,"",host)
                if (fam=="") fam="url-host"
                if (host != "") print host"|threatfox|"fam >> domainsout
              }
              else if (typ ~ /_hash$/) { if (fam=="") fam=typ; print val"|threatfox|"fam >> hashesout }
            }'
      else
        awk -F',' -v ipsout="$tmpips" -v domainsout="$tmpdomains" -v hashesout="$tmphashes" '
          !/^#/ && NF>=4 {
            val=$3; typ=$4
            gsub(/"/,"",val); gsub(/"/,"",typ)
            gsub(/^[ \t\r]+|[ \t\r]+$/,"",val); gsub(/^[ \t\r]+|[ \t\r]+$/,"",typ)
            if (typ=="ip:port") { sub(/:[0-9]+$/,"",val); print val"|threatfox|ip" >> ipsout }
            else if (typ=="domain") { print val"|threatfox|domain" >> domainsout }
            else if (typ=="url") {
              host=val
              sub(/^[A-Za-z]+:\/\//,"",host)
              sub(/[\/:?].*$/,"",host)
              if (host != "") print host"|threatfox|url-host" >> domainsout
            }
            else if (typ ~ /_hash$/) { print val"|threatfox|"typ >> hashesout }
          }' "$feedsroot/threatfox.raw"
      fi
    fi
  fi

  if [ -s "$tmpips" ]; then
    dedupindicators "$tmpips"
    mv "$tmpips" "$feedsroot/ips.txt"
  else
    rm -f "$tmpips"
    echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - WARNING: Feed normalization produced zero IP indicators; leaving the previous ips.txt in place." >> "$logfile"
  fi

  if [ -s "$tmpdomains" ]; then
    dedupindicators "$tmpdomains"
    mv "$tmpdomains" "$feedsroot/domains.txt"
  else
    rm -f "$tmpdomains"
    [ -f "$feedsroot/domains.txt" ] || : > "$feedsroot/domains.txt"
  fi

  if [ -s "$tmphashes" ]; then
    dedupindicators "$tmphashes"
    mv "$tmphashes" "$feedsroot/hashes.txt"
  else
    rm -f "$tmphashes"
    [ -f "$feedsroot/hashes.txt" ] || : > "$feedsroot/hashes.txt"
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# updatefeeds is the feed-manager orchestrator: fetch each enabled source, then normalize.

updatefeeds()
{
  local okcount=0 failcount=0

  mkdir -m 755 -p "$feedsroot/meta"

  echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - INFO: Starting IoC feed refresh cycle." >> "$logfile"

  if [ "$enablefeodo" -eq 1 ]; then
    if fetchfeedsource "Feodo Tracker" "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt" "$feedsroot/feodo.raw" "$feedsroot/meta/feodo.meta"; then
      okcount=$((okcount+1))
      echo -e "  ${CGreen}*${CClear} Feodo Tracker: fetched ${CGreen}$(wc -l < "$feedsroot/feodo.raw" 2>/dev/null | tr -d ' ')${CClear} indicators"
    else
      failcount=$((failcount+1))
      echo -e "  ${CRed}*${CClear} Feodo Tracker: fetch failed (see log)"
    fi
  fi

  if [ "$feedsdegraded" -eq 0 ]; then
    if [ "$enablespamhaus" -eq 1 ]; then
      if fetchfeedsource "Spamhaus DROP" "https://www.spamhaus.org/drop/drop.txt" "$feedsroot/spamhaus_drop.raw" "$feedsroot/meta/spamhaus_drop.meta"; then
        okcount=$((okcount+1))
        echo -e "  ${CGreen}*${CClear} Spamhaus DROP: fetched ${CGreen}$(wc -l < "$feedsroot/spamhaus_drop.raw" 2>/dev/null | tr -d ' ')${CClear} netblocks"
      else
        failcount=$((failcount+1))
        echo -e "  ${CRed}*${CClear} Spamhaus DROP: fetch failed (see log)"
      fi
      if fetchfeedsource "Spamhaus EDROP" "https://www.spamhaus.org/drop/edrop.txt" "$feedsroot/spamhaus_edrop.raw" "$feedsroot/meta/spamhaus_edrop.meta"; then
        okcount=$((okcount+1))
        echo -e "  ${CGreen}*${CClear} Spamhaus EDROP: fetched ${CGreen}$(wc -l < "$feedsroot/spamhaus_edrop.raw" 2>/dev/null | tr -d ' ')${CClear} netblocks"
      else
        failcount=$((failcount+1))
        echo -e "  ${CRed}*${CClear} Spamhaus EDROP: fetch failed (see log)"
      fi
    fi

    if [ "$enableurlhaus" -eq 1 ]; then
      if fetchfeedsource "URLhaus" "https://urlhaus.abuse.ch/downloads/hostfile/" "$feedsroot/urlhaus.raw" "$feedsroot/meta/urlhaus.meta"; then
        okcount=$((okcount+1))
        echo -e "  ${CGreen}*${CClear} URLhaus: fetched ${CGreen}$(wc -l < "$feedsroot/urlhaus.raw" 2>/dev/null | tr -d ' ')${CClear} malicious hosts"
      else
        failcount=$((failcount+1))
        echo -e "  ${CRed}*${CClear} URLhaus: fetch failed (see log)"
      fi
    fi

    if [ "$enablethreatfox" -eq 1 ]; then
      if fetchthreatfox; then
        okcount=$((okcount+1))
        echo -e "  ${CGreen}*${CClear} ThreatFox: fetched ${CGreen}$(wc -l < "$feedsroot/threatfox.raw" 2>/dev/null | tr -d ' ')${CClear} raw IOC records"
      else
        failcount=$((failcount+1))
        echo -e "  ${CRed}*${CClear} ThreatFox: fetch failed (see log)"
      fi
    fi
  fi

  normalizefeeds

  echo -e "  ${CGreen}*${CClear} Normalized into ${CGreen}$(cat "$feedsroot/ips.txt" "$feedsroot/domains.txt" "$feedsroot/hashes.txt" 2>/dev/null | wc -l | tr -d ' ')${CClear} deduped IoC indicators (${CGreen}${okcount}${CClear} sources ok, ${CRed}${failcount}${CClear} failed)"
  echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - INFO: IoC feed refresh cycle complete ($okcount ok, $failcount failed)." >> "$logfile"
}

# -------------------------------------------------------------------------------------------------------------------------
# checkfeedupdate is the cadence gate called every main-loop tick

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
    updatefeeds
    echo "$nowepoch" > "$stampfile"
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
    updatefeeds
    date +%s > "$feedsroot/meta/.last_update"
    echo ""
    echo -e "${CGreen}Feed refresh complete.${CClear}"
  fi

  echo ""
  read -rsp $'Press any key to continue...\n' -n1 key
  if [ "$timerpaused" -eq 1 ]; then renderdashboard; else timer=$timerloop; fi
}

# -------------------------------------------------------------------------------------------------------------------------
# feedsourcecounts prints a compact "source=N source=N" breakdown across all three canonical files.

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
        if (s == "spamhaus-drop" || s == "spamhaus-edrop") s = "spamhaus"
        c[s]++
      }
    }
    END { for (k in c) printf "%s=%d ", k, c[k] }
  '
}

feedsoldestfetch()
{
  local src oldestfile="" oldestmt="" metafile mt
  for src in feodo spamhaus_drop spamhaus_edrop urlhaus threatfox; do
    metafile="$feedsroot/meta/$src.meta"
    [ -f "$metafile" ] || continue
    mt="$(date -r "$metafile" +%s 2>/dev/null)"
    [ -z "$mt" ] && continue
    if [ -z "$oldestmt" ] || [ "$mt" -lt "$oldestmt" ]; then
      oldestmt="$mt"; oldestfile="$metafile"
    fi
  done
  if [ -n "$oldestfile" ]; then
    date -r "$oldestfile" +'%H:%M'
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
   echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - INFO: ${msgStr} the shared AMTM email library script file to support email notifications..." >> "$logfile"

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
       echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - **ERROR**: Unable to download the shared AMTM email library script file [$CUSTOM_EMAIL_LIBName]." >> "$logfile"
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
       echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - **ERROR**: Email library script [$CUSTOM_EMAIL_LIBFile] *NOT* FOUND." >> "$logfile"
       return 1
   fi

   if [ $# -lt 3 ] || [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]
   then
       printf "\33[2K\r"
       printf "${CRed}\r[ERROR: INSUFFICIENT email parameters]${CClear}"
       sleep 5
       echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - **ERROR**: INSUFFICIENT email parameters." >> "$logfile"
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
     printf "${CGreen}\r[Email notification was sent successfully ($statustext)]${CClear}"
     echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - INFO: Email notification was sent successfully [$2]" >> "$logfile"
     sleep 5
   else
     printf "\33[2K\r"
     printf "${CRed}\r[ERROR: Failure to send email notification (Error Code: $retCode - $statustext).]${CClear}"
     echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - **ERROR**: Failure to send email notification [$2]" >> "$logfile"
     sleep 5
   fi

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
# sendmessage is the single shared entry point every IOCMON alert type routes through

sendmessage()
{
  local success="$1" kind="$2" indicator="$3" source="$4" detail="$5"

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
      test)
        emailSubject="TEST: IOCMON email notification test"
        emailBodyTitle="$emailSubject"
        {
        printf "<b>Date/Time:</b> $(date +'%b %d %Y %X')\n"
        printf "\n"
        printf "This is a test email requested via 'iocmon.sh -email' to confirm AMTM email notifications are\n"
        printf "configured correctly. If you received this, IOCMON's email pipeline is working.\n"
        } > "$tmpEMailBodyFile"
        ;;
      simulated)
        emailSubject="TEST: Simulated IOC detection ($indicator)"
        emailBodyTitle="$emailSubject"
        {
        printf "<b>Date/Time:</b> $(date +'%b %d %Y %X')\n"
        printf "\n"
        printf "This is a <b>SIMULATED</b> detection triggered via the (T)est hotkey to confirm IOCMON's full\n"
        printf "detection-to-alert pipeline is working. <b>No real compromise has been detected.</b>\n"
        printf "\n"
        printf "<b>Indicator:</b> %s\n<b>Feed source:</b> %s\n<b>Detail:</b> %s\n" "$indicator" "$source" "$detail"
        } > "$tmpEMailBodyFile"
        ;;
      conntrack)
        emailSubject="ALERT: Connection to known-malicious IP ($indicator)"
        emailBodyTitle="$emailSubject"
        {
        printf "<b>Date/Time:</b> $(date +'%b %d %Y %X')\n"
        printf "\n"
        printf "<b>IOCMON</b> detected an active connection (<b>%s</b>, local device -&gt; remote host), which matches the <b>%s</b> IoC feed\n" "$indicator" "$source"
        printf "(family: %s). This address may be a botnet command-and-control server or other malicious host.\n" "$detail"
        printf "\n"
        printf "Please review connected devices and investigate for compromise.\n"
        } > "$tmpEMailBodyFile"
        ;;
      dns)
        if [ "$source" = "dns-tunnel-heuristic" ]; then
          emailSubject="ALERT: Suspicious DNS query pattern detected ($indicator)"
          emailBodyTitle="$emailSubject"
          {
          printf "<b>Date/Time:</b> $(date +'%b %d %Y %X')\n"
          printf "\n"
          printf "<b>IOCMON</b> observed a DNS query (<b>%s</b>, local device -&gt; queried domain) that matches a\n" "$indicator"
          printf "behavioral DNS-tunneling/exfiltration heuristic - %s.\n" "$detail"
          printf "\n"
          printf "This is a <b>pattern-based suspicion, not a confirmed threat-intelligence match</b> - it is not\n"
          printf "present in any known-malicious-domain feed. Please verify manually before treating this as a\n"
          printf "confirmed compromise; a legitimate service with an unusually long or high-subdomain-churn\n"
          printf "hostname can trigger this. If this is expected/benign, add the domain to the DNS exceptions\n"
          printf "list (Advanced Settings - DNS Watch &amp; Tunneling Detection) to stop it recurring.\n"
          } > "$tmpEMailBodyFile"
        else
          emailSubject="ALERT: DNS query for known-malicious domain ($indicator)"
          emailBodyTitle="$emailSubject"
          {
          printf "<b>Date/Time:</b> $(date +'%b %d %Y %X')\n"
          printf "\n"
          printf "<b>IOCMON</b> observed a DNS query (<b>%s</b>, local device -&gt; queried domain), which matches the <b>%s</b> IoC feed\n" "$indicator" "$source"
          printf "(family: %s). A device on your network may be compromised or contacting a malware-distribution site.\n" "$detail"
          } > "$tmpEMailBodyFile"
        fi
        ;;
      auth)
        emailSubject="WARNING: Possible brute-force login attempts from $indicator"
        emailBodyTitle="$emailSubject"
        {
        printf "<b>Date/Time:</b> $(date +'%b %d %Y %X')\n"
        printf "\n"
        printf "<b>IOCMON</b> detected repeated failed login attempts against the <b>%s</b> service from\n" "$source"
        printf "<b>%s</b> (%s). Please verify this is not an authorized user and consider blocking this address.\n" "$indicator" "$detail"
        } > "$tmpEMailBodyFile"
        ;;
      fsintegrity)
        emailSubject="ALERT: Filesystem-integrity event - $indicator"
        emailBodyTitle="$emailSubject"
        {
        printf "<b>Date/Time:</b> $(date +'%b %d %Y %X')\n"
        printf "\n"
        printf "<b>IOCMON</b> flagged a filesystem-integrity event on <b>%s</b>.\n" "$indicator"
        printf "<b>Reason:</b> %s (%s)\n" "$source" "$detail"
        printf "\n"
        printf "Please review this file/change as soon as possible.\n"
        } > "$tmpEMailBodyFile"
        ;;
      cron)
        emailSubject="ALERT: Unexpected new cron entry detected"
        emailBodyTitle="$emailSubject"
        {
        printf "<b>Date/Time:</b> $(date +'%b %d %Y %X')\n"
        printf "\n"
        printf "<b>IOCMON</b> detected a new scheduled task (cru entry) that it did not create:\n"
        printf "<b>%s</b>\n" "$indicator"
        printf "\n"
        printf "This can indicate cron-based persistence from malware. Please review with 'cru l'.\n"
        } > "$tmpEMailBodyFile"
        ;;
      *)
        emailSubject="ALERT: IOCMON detected a security event ($kind)"
        emailBodyTitle="$emailSubject"
        {
        printf "<b>Date/Time:</b> $(date +'%b %d %Y %X')\n"
        printf "\n"
        printf "<b>Indicator:</b> %s\n<b>Source:</b> %s\n<b>Detail:</b> %s\n" "$indicator" "$source" "$detail"
        } > "$tmpEMailBodyFile"
        ;;
    esac

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
      printf "<b>Date/Time:</b> %s\n" "$(date +'%b %d %Y %X')"
      printf "\n"
      printf "<b>IOCMON</b> detected <b>%s</b> separate security events during a single scan cycle. Rather than send\n" "$count"
      printf "%s separate emails, they are grouped below:\n" "$count"
      printf "\n"
      local i=0 bkind bindicator bsource bdetail
      while IFS="$tab" read -r bkind bindicator bsource bdetail; do
        i=$((i+1))
        printf "<b>%d. [%s]</b> %s\n" "$i" "$bkind" "$bindicator"
        printf "&nbsp;&nbsp;&nbsp;&nbsp;Source: %s<br>&nbsp;&nbsp;&nbsp;&nbsp;Detail: %s\n" "$bsource" "$bdetail"
        printf "\n"
      done < "$batchfile"
      printf "Please review each item above.\n"
    } > "$tmpEMailBodyFile"

    _SendEMailNotification_ "IOCMON v$version" "$emailSubject" "$tmpEMailBodyFile" "$emailBodyTitle"

  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# queueemailalert/flushemailbatch become one grouped email instead of one email per alert

queueemailalert()
{
  local kind="$1" indicator="$2" source="$3" detail="$4"

  resolvestateroot
  if [ -z "$stateroot" ]; then
    sendmessage 1 "$kind" "$indicator" "$source" "$detail"
    return
  fi

  mkdir -m 755 -p "$stateroot"
  printf '%s\t%s\t%s\t%s\n' "$kind" "$indicator" "$source" "$detail" >> "$stateroot/email_batch.pending"
}

flushemailbatch()
{
  resolvestateroot
  [ -n "$stateroot" ] || return

  local batchfile="$stateroot/email_batch.pending" sendfile="$stateroot/email_batch.sending" count tab

  [ -s "$batchfile" ] || return
  mv "$batchfile" "$sendfile"

  count="$(wc -l < "$sendfile" | tr -d ' ')"

  if [ "$count" -le 1 ]; then
    local kind indicator source detail
    tab="$(printf '\t')"
    IFS="$tab" read -r kind indicator source detail < "$sendfile"
    sendmessage 1 "$kind" "$indicator" "$source" "$detail"
  else
    sendbatchmessage "$sendfile" "$count"
  fi

  rm -f "$sendfile"
}

# -------------------------------------------------------------------------------------------------------------------------
# raisealert is the single entry point every detection check routes an IOC/brute-force match through.

raisealert()
{
  local kind="$1" indicator="$2" source="$3" detail="$4" dedupkey="${5:-$2}"
  local key="${kind}|${dedupkey}" nowepoch cooldownsec=21600 lastepoch=0

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

  echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - WARNING: IOC match ($kind): $indicator matched $source ($detail)." >> "$logfile"

  if [ -n "$stateroot" ]; then
    local alertline pendingfile="$stateroot/alert_pending" pendingcount=0
    alertline="$(date +'%b %d %Y %X') | $kind | $indicator | $source | $detail"
    echo "$alertline" >> "$stateroot/ioc_alerts.log"

    [ -f "$pendingfile" ] && pendingcount="$(head -n1 "$pendingfile" 2>/dev/null)"
    validateint "$pendingcount" 0 || pendingcount=0
    pendingcount=$((pendingcount + 1))
    { echo "$pendingcount"; echo "$alertline"; } > "$pendingfile"
  fi

  queueemailalert "$kind" "$indicator" "$source" "$detail"
}

# -------------------------------------------------------------------------------------------------------------------------
# checkconntrack reads /proc/net/nf_conntrack, extracting each connection's original-direction src=/dst= IP pair.

checkconntrack()
{
  conntrackchecked=0

  [ "$enableconntrackwatch" -eq 1 ] || return

  resolvefeedsroot
  [ -z "$feedsroot" ] && return

  local ipsfile="$feedsroot/ips.txt"
  [ -s "$ipsfile" ] || return

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

  echo "$pairlist" | awk -F'|' '
    FNR==NR {
      if ($1 !~ /\//) { plain[$1] = $2"|"$3 } else { cidrs[$1] = $2"|"$3 }
      next
    }
    {
      src = $1; dst = $2
      if (dst == "") next
      if (dst in plain) { print src"|"dst"|"plain[dst]; next }
      for (c in cidrs) {
        split(c, parts, "/")
        netip = parts[1]; masklen = parts[2] + 0
        split(dst, a, "."); ipint = (a[1]*16777216)+(a[2]*65536)+(a[3]*256)+a[4]
        split(netip, b, "."); netint = (b[1]*16777216)+(b[2]*65536)+(b[3]*256)+b[4]
        divisor = 2 ^ (32 - masklen)
        if (int(ipint/divisor) == int(netint/divisor)) { print src"|"dst"|"cidrs[c]; break }
      }
    }
  ' "$ipsfile" - | while IFS='|' read -r srcip matchedip source family; do
    raisealert "conntrack" "${srcip}->${matchedip}" "$source" "$family" "$matchedip"
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# dnsquerylogenabled/enablednsquerylogging manage the one-time opt-in dnsmasq change checkdns() depends on

dnsquerylogenabled()
{
  grep -qF "log-queries" /jffs/configs/dnsmasq.conf.add 2>/dev/null
}

# -------------------------------------------------------------------------------------------------------------------------
# resolvednslogfile finds where dnsmasq is actually writing its query log.

resolvednslogfile()
{
  local facility
  facility="$(grep -E '^log-facility=' /etc/dnsmasq.conf 2>/dev/null | tail -n1 | cut -d= -f2-)"
  if [ -n "$facility" ] && [ -f "$facility" ]; then
    echo "$facility"
  else
    echo "/tmp/syslog.log"
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# indnsexceptionlist tests $1 (a domain) for exact membership in $dnsexceptions

indnsexceptionlist()
{
  local domain="$1" ex
  for ex in $dnsexceptions; do
    case "$domain" in
      "$ex"|*".$ex") return 0 ;;
    esac
  done
  return 1
}

enablednsquerylogging()
{
  if dnsquerylogenabled; then
    echo -e "${CGreen}DNS query logging is already enabled.${CClear}"
    return 0
  fi

  echo "log-queries" >> /jffs/configs/dnsmasq.conf.add
  echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - INFO: Enabled dnsmasq query logging (log-queries) via dnsmasq.conf.add." >> "$logfile"
  service restart_dnsmasq >/dev/null 2>&1
  echo -e "${CGreen}DNS query logging enabled and dnsmasq restarted.${CClear}"
}

# -------------------------------------------------------------------------------------------------------------------------
# checkdns tails new syslog lines since the last check

checkdns()
{
  dnschecked=0
  dnsqueriedcount=0

  [ "$enablednswatch" -eq 1 ] || return

  if ! dnsquerylogenabled; then
    if [ "$dnsquerylogwarned" != "1" ]; then
      echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - WARNING: DNS watch is enabled but dnsmasq query logging is off - enable it from the Configuration Menu." >> "$logfile"
      dnsquerylogwarned=1
    fi
    return
  fi

  resolvefeedsroot
  [ -z "$feedsroot" ] && return

  local domainsfile="$feedsroot/domains.txt"
  [ -s "$domainsfile" ] || return

  local synclog
  synclog="$(resolvednslogfile)"
  [ -f "$synclog" ] || return

  local linecount lastcount=0 newlines checkpointfile=""
  linecount="$(wc -l < "$synclog" | tr -d ' ')"

  resolvestateroot
  if [ -n "$stateroot" ]; then
    mkdir -m 755 -p "$stateroot"
    checkpointfile="$stateroot/dns_checkpoint"
    [ -f "$checkpointfile" ] && lastcount="$(cat "$checkpointfile" 2>/dev/null)"
    [ -z "$lastcount" ] && lastcount=0
  elif [ -n "$dnscheckpointcache" ]; then
    lastcount="$dnscheckpointcache"
  fi

  [ "$linecount" -lt "$lastcount" ] && lastcount=0
  newlines=$((linecount - lastcount))

  [ -n "$checkpointfile" ] && echo "$linecount" > "$checkpointfile"
  dnscheckpointcache="$linecount"

  [ "$newlines" -le 0 ] && return

  dnschecked="$newlines"
  dnslastcheck=$(date +'%H:%M')

  local dnsmasqlines
  dnsmasqlines="$(tail -n "$newlines" "$synclog" | grep -Fc 'dnsmasq')"

  local querypairs
  querypairs="$(tail -n "$newlines" "$synclog" | grep -F 'dnsmasq' | awk '
    {
      domain=""; src=""
      for (i=1; i<=NF; i++) {
        if ($i ~ /^query\[[A-Za-z]+\]$/) { domain=$(i+1) }
        if ($i=="from" && (i+1)<=NF) { src=$(i+1) }
      }
      if (domain!="" && src!="") print domain"|"src
    }
  ' | sort -u)"

  if [ -z "$querypairs" ]; then
    if [ "$dnsmasqlines" -gt 0 ] && [ "$dnsquerymissingwarned" != "1" ]; then
      echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - WARNING: DNS watch sees dnsmasq activity in the log but no query[...] lines. Two known causes: (1) log-queries is configured but dnsmasq hasn't picked it up yet - try 'service restart_dnsmasq'; (2) DHCP hands LAN clients a DNS server that isn't this router's own LAN IP, so queries never pass through this dnsmasq at all - check the DHCP Server DNS setting in the web UI if (1) doesn't help." >> "$logfile"
      dnsquerymissingwarned=1
    fi
    return
  fi
  dnsquerymissingwarned=0

  dnsqueriedcount="$(echo "$querypairs" | wc -l | tr -d ' ')"

  if [ "$enablednstunnel" -eq 1 ]; then
    echo "$querypairs" | awk -F'|' -v namelen="$dnstunnelnamelen" '
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
    ' | while IFS='|' read -r kind srcip a b; do
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
  fi

  echo "$querypairs" | awk -F'|' '
    FNR==NR { d[$1] = $2"|"$3; next }
    {
      domain = $1; src = $2
      if (domain in d) print src"|"domain"|"d[domain]
    }
  ' "$domainsfile" - | while IFS='|' read -r srcip matcheddomain source family; do
    if indnsexceptionlist "$matcheddomain"; then
      echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - INFO: DNS query for $matcheddomain from $srcip matched the $source IoC feed but is on the DNS exception list - no alert raised." >> "$logfile"
    else
      raisealert "dns" "${srcip}->${matcheddomain}" "$source" "$family" "$matcheddomain"
    fi
  done
}

# -------------------------------------------------------------------------------------------------------------------------
# checkauth does a rate-based grep of new syslog lines for dropbear/httpd auth-failure patterns

checkauth()
{
  authchecked=0

  [ "$enableauthwatch" -eq 1 ] || return

  local synclog="/tmp/syslog.log"
  [ -f "$synclog" ] || return

  local linecount lastcount=0 newlines checkpointfile=""
  linecount="$(wc -l < "$synclog" | tr -d ' ')"

  resolvestateroot
  if [ -n "$stateroot" ]; then
    mkdir -m 755 -p "$stateroot"
    checkpointfile="$stateroot/auth_checkpoint"
    [ -f "$checkpointfile" ] && lastcount="$(cat "$checkpointfile" 2>/dev/null)"
    [ -z "$lastcount" ] && lastcount=0
  elif [ -n "$authcheckpointcache" ]; then
    lastcount="$authcheckpointcache"
  fi

  [ "$linecount" -lt "$lastcount" ] && lastcount=0
  newlines=$((linecount - lastcount))

  [ -n "$checkpointfile" ] && echo "$linecount" > "$checkpointfile"
  authcheckpointcache="$linecount"

  [ "$newlines" -le 0 ] && return

  authchecked="$newlines"
  authlastcheck=$(date +'%H:%M')

  local nowepoch cutoff dropbearips httpdips dropbearlines
  nowepoch=$(date +%s)
  cutoff=$((nowepoch - authslowwindowhrs * 3600))

  dropbearlines="$(tail -n "$newlines" "$synclog" | grep -F 'dropbear' | grep -F 'Bad password attempt')"
  if [ -n "$dropbearlines" ]; then
    echo "$dropbearlines" >> "$dropbearlogfile"
    trimlogfile "$dropbearlogfile" "$logsize"
  fi
  dropbearips="$(echo "$dropbearlines" | grep -oE 'from [0-9]{1,3}(\.[0-9]{1,3}){3}' | awk '{print $2}')"

  httpdips="$(tail -n "$newlines" "$synclog" | grep -iF 'httpd' | grep -iE 'login.?fail|invalid.?password|authentication.?fail' | \
    grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')"

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
  local firstrun=0 var newval oldval
  nvramlastcheck=$(date +'%H:%M')
  [ -s "$baseline" ] || firstrun=1

  : > "$newbaseline"
  for var in $nvramwatchvars; do
    newval="$(nvram get "$var" 2>/dev/null | tr '\n' ' ')"
    newval="${newval% }"
    echo "${var}=${newval}" >> "$newbaseline"

    if [ "$firstrun" -eq 0 ]; then
      oldval="$(awk -F'=' -v v="$var" '$1==v{sub(/^[^=]*=/,""); print; exit}' "$baseline" 2>/dev/null)"
      if [ "$newval" != "$oldval" ]; then
        raisealert "nvram" "$var" "nvram-change" "changed from '${oldval:-<empty>}' to '${newval:-<empty>}'"
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
  echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - WARNING: Quarantined $path -> ${path}.iocmon-quarantine (execute bit stripped, not deleted)." >> "$logfile"
}

# -------------------------------------------------------------------------------------------------------------------------
# hashmatchcheck computes whichever of md5/sha1/sha256 are available for one file and checks them against feeds/hashes.txt.

hashmatchcheck()
{
  local path="$1" hashesfile="$2" md5="" sha1="" sha256="" match

  which md5sum >/dev/null 2>&1 && md5="$(md5sum "$path" 2>/dev/null | awk '{print $1}')"
  which sha1sum >/dev/null 2>&1 && sha1="$(sha1sum "$path" 2>/dev/null | awk '{print $1}')"
  which sha256sum >/dev/null 2>&1 && sha256="$(sha256sum "$path" 2>/dev/null | awk '{print $1}')"

  match="$(printf '%s\n%s\n%s\n' "$md5" "$sha1" "$sha256" | grep -v '^$' | awk -F'|' '
    FNR==NR { h[$1] = $2"|"$3; next }
    { if ($0 in h) print $0"|"h[$0] }
  ' "$hashesfile" -)"

  [ -z "$match" ] && return

  echo "$match" | while IFS='|' read -r matchedhash source family; do
    raisealert "fsintegrity" "$path" "$source" "hash match $matchedhash ($family)"
    quarantinefile "$path"
  done
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
      raisealert "fsintegrity" "$path" "ssh-directory-change" "$changetype - review immediately, not hash-matched"
      ;;
  esac

  base="${path##*/}"
  dir="${path%/*}"
  case " $fsstartupscripts " in
    *" $base "*)
      [ "$dir" = "/jffs/scripts" ] && raisealert "fsintegrity" "$path" "startup-script-edit" "$changetype - review regardless of hash match"
      ;;
  esac

  case "$base" in
    *.conf.add)
      [ "$dir" = "/jffs/configs" ] && raisealert "fsintegrity" "$path" "router-config-override" "$changetype - review regardless of hash match (e.g. dnsmasq DNS/upstream-resolver tampering)"
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

  case " $fsstartupscripts " in
    *" $base "*)
      [ "$dir" = "/jffs/scripts" ] && raisealert "fsintegrity" "$path" "startup-script-deleted" "file deleted - review regardless of cause"
      ;;
  esac

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
    echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - ERROR: Filesystem-integrity scan hit $(wc -l < "$scanerrors" | tr -d ' ') find error(s) - see $scanerrors on the router. First: $(head -n1 "$scanerrors")" >> "$logfile"
  fi

  if [ -z "$dircount" ] || [ "$dircount" -eq 0 ]; then
    echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - WARNING: Filesystem-integrity scan found none of the configured fswatchdirs on disk - check the path list in Advanced Settings." >> "$logfile"
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
    echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - INFO: Filesystem-integrity baseline established ($fsscannedcount files across $dircount directories)." >> "$logfile"
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
  trimlogfile "$lastnewfile" "$logsize"
  trimlogfile "$lastmodfile" "$logsize"
  trimlogfile "$lastdelfile" "$logsize"
  trimlogfile "$lastpermfile" "$logsize"

  {
    printf '[%s1%s] New files list: %s (%s new entries)\n' "$CGreen" "$CClear" "$lastnewfile" "$fsnewcount"
    printf '[%s2%s] Modified files list: %s (%s new entries)\n' "$CGreen" "$CClear" "$lastmodfile" "$fsmodcount"
    printf '[%s3%s] Deleted files list: %s (%s new entries)\n' "$CGreen" "$CClear" "$lastdelfile" "$fsdelcount"
    printf '[%s4%s] Permission-changed files list: %s (%s new entries)\n' "$CGreen" "$CClear" "$lastpermfile" "$fspermcount"
  } >> "$scansummary"

  echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - INFO: Filesystem-integrity scan complete: $fsscannedcount files scanned across $dircount directories; $fsnewcount new and $fsmodcount modified file(s) checked against known-malware hashes; $fsdelcount deletion(s) detected in critical watched paths; $fspermcount permission-only change(s) detected." >> "$logfile"

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
# checkcronbaseline alerts on any cru entry that appeared since the last check

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

checkcronbaseline()
{
  [ "$enablecrondiff" -eq 1 ] || return

  local newcron="$stateroot/cron_baseline.db.new" oldcron="$stateroot/cron_baseline.db" newentries

  cru l 2>/dev/null | sort > "$newcron"

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
      echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - INFO: New cru entry matches the cron exceptions list, not alerting: $entry" >> "$logfile"
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
      echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - INFO: New Entware cron entry matches the cron exceptions list, not alerting: $entry" >> "$logfile"
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
# fsintegritycheck is the main-loop entry point

# -------------------------------------------------------------------------------------------------------------------------
# fsintegritylock/fsintegrityunlock guard against two overlapping scans (main loop cadence vs -fsintegrity cron vs forced) racing on the same manifest/state files.

fsintegritylock()
{
  local lockfile="$addonsdir/fsintegrity.lock" lockpid
  if [ -f "$lockfile" ]; then
    lockpid="$(cat "$lockfile" 2>/dev/null)"
    if [ -n "$lockpid" ] && [ "$lockpid" != "$$" ] && kill -0 "$lockpid" 2>/dev/null; then
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
    echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - INFO: Filesystem-integrity scan skipped - another scan is already in progress." >> "$logfile"
    return 1
  fi
  checkfsintegrity
  checkcronbaseline
  checkentwarecron
  checkfirewallrules
  fsintegrityunlock
  return 0
}

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
# acknowledgealert clears the persistent alert_pending marker - the only way the red banner goes away.

acknowledgealert()
{
  resolvestateroot
  if [ -n "$stateroot" ] && [ -f "$stateroot/alert_pending" ]; then
    rm -f "$stateroot/alert_pending"
    echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - INFO: Security alert banner acknowledged." >> "$logfile"
  fi
  renderdashboard
}

# -------------------------------------------------------------------------------------------------------------------------
# vioclog opens the permanent IOC detection log in nano.

vioclog()
{
  resolvestateroot
  local viewfile="" emptymsg="No dropbear login-failure attempts have been logged yet."

  if [ "$alertviewmode" = "dropbear" ]; then
    viewfile="$dropbearlogfile"
  else
    emptymsg="No IoC detections have been logged yet."
    [ -n "$stateroot" ] && viewfile="$stateroot/ioc_alerts.log"
  fi

  if [ -z "$viewfile" ] || [ ! -s "$viewfile" ]; then
    clear
    echo -e "${CYellow}${emptymsg}${CClear}"
    echo ""
    read -rsp $'Press any key to continue...\n' -n1 key
  else
    export TERM=linux
    nano +999999 --linenumbers "$viewfile"
  fi
  renderdashboard
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

  if [ -z "$viewfile" ] || [ ! -s "$viewfile" ]; then
    clear
    echo -e "${CYellow}No $label have been logged yet.${CClear}"
    echo ""
    read -rsp $'Press any key to continue...\n' -n1 key
  else
    export TERM=linux
    nano +999999 --linenumbers "$viewfile"
  fi
  renderdashboard
}

# -------------------------------------------------------------------------------------------------------------------------
# testdetection picks one real indicator at random out of the currently loaded feeds

testdetection()
{
  clear
  echo -e "${CGreen}[Running Simulated Detection Test]${CClear}"
  echo ""

  resolvefeedsroot

  local candidatefile=""
  if [ -n "$feedsroot" ] && [ -s "$feedsroot/ips.txt" ]; then
    candidatefile="$feedsroot/ips.txt"
  elif [ -n "$feedsroot" ] && [ -s "$feedsroot/domains.txt" ]; then
    candidatefile="$feedsroot/domains.txt"
  elif [ -n "$feedsroot" ] && [ -s "$feedsroot/hashes.txt" ]; then
    candidatefile="$feedsroot/hashes.txt"
  fi

  if [ -z "$candidatefile" ]; then
    echo -e "${CRed}ERROR: No feed data is loaded yet - refresh feeds first, then try again.${CClear}"
  else
    local randline indicator source family
    randline="$(awk 'BEGIN{srand()} {a[NR]=$0} END{if (NR>0) print a[int(rand()*NR)+1]}' "$candidatefile")"
    IFS='|' read -r indicator source family <<EOF
$randline
EOF
    echo -e "Simulating a detection of ${CGreen}${indicator}${CClear} (from the ${CGreen}${source}${CClear} feed)..."
    echo ""
    raisealert "simulated" "$indicator" "$source" "$family - SIMULATED TEST via (T) hotkey, not a real detection"
    flushemailbatch
    blanklineguard
    echo -e "${CGreen}Simulated detection logged. Check the IoC log ((V) from the main screen) and the red banner${CClear}"
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

  cru d IOCMONUpdate >/dev/null 2>&1
  cru d IOCMONFeeds >/dev/null 2>&1
  cru d IOCMONFsIntegrity >/dev/null 2>&1

  if [ -f /jffs/scripts/services-start ]; then
    sed -i '/# iocmon-cron/d' /jffs/scripts/services-start
  else
    echo '#!/bin/sh' > /jffs/scripts/services-start
    chmod 755 /jffs/scripts/services-start
  fi

  if [ "$schedule" -eq 1 ]; then
    cru a IOCMONUpdate "$schedulemin $schedulehrs * * * sh $apppath -autoupdate"
    echo "cru a IOCMONUpdate \"$schedulemin $schedulehrs * * * sh $apppath -autoupdate\" # iocmon-cron" >> /jffs/scripts/services-start
  fi

  cru a IOCMONFeeds "0 */$feedupdatehrs * * * sh $apppath -updatefeeds"
  echo "cru a IOCMONFeeds \"0 */$feedupdatehrs * * * sh $apppath -updatefeeds\" # iocmon-cron" >> /jffs/scripts/services-start

  cru a IOCMONFsIntegrity "0 */$fsintegrityhrs * * * sh $apppath -fsintegrity"
  echo "cru a IOCMONFsIntegrity \"0 */$fsintegrityhrs * * * sh $apppath -fsintegrity\" # iocmon-cron" >> /jffs/scripts/services-start
}

# -------------------------------------------------------------------------------------------------------------------------
# autostart adds/removes the post-mount hook that launches IOCMON's background SCREEN monitor on reboot

autostart()
{
  if [ -f /jffs/scripts/services-start ]; then
    sed -i '/# iocmon-autostart/d' /jffs/scripts/services-start
  fi

  if [ -f /jffs/scripts/post-mount ]; then
    sed -i '/# iocmon-autostart/d' /jffs/scripts/post-mount
  else
    echo '#!/bin/sh' > /jffs/scripts/post-mount
    chmod 755 /jffs/scripts/post-mount
  fi

  if [ "$autostart" -eq 1 ]; then
    echo "(sleep 30 && sh $apppath -screen -now) & # iocmon-autostart" >> /jffs/scripts/post-mount
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# vresetdefaults erases iocmon.cfg and restarts the script fresh, so every setting reverts to its script default.

vresetdefaults()
{
  clear
  echo -e "${InvGreen} ${InvDkGray}${CWhite} Reset IOCMON to Default Settings                                                                                                        ${CClear}"
  echo -e "${InvGreen} ${CClear}"
  echo -e "${InvGreen} ${CClear} This erases $config and restarts IOCMON: every toggle, threshold, and list (watched/${CClear}"
  echo -e "${InvGreen} ${CClear} excluded paths, cron/DNS exceptions, feed sources, etc.) reverts to its shipped default,${CClear}"
  echo -e "${InvGreen} ${CClear} and you will be walked through initial setup (drive selection) again. This is irreversible.${CClear}"
  echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
  echo ""
  echo -e "Do you wish to proceed?"
  if promptyn "[y/n]: "; then
    rm -f "$config"
    echo ""
    echo -e "${CGreen}Configuration erased. Restarting IOCMON with default settings...${CClear}"
    sleep 2
    exec sh "$apppath" -noswitch
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# vupdate checks both tracks (per TAILMON's own vupdate), lets the user switch tracks, and downloads/installs the chosen one.

vupdate()
{
  local trackdisp remoteversion remotelabel remoteurl selupdate

  while true; do
    updatecheck
    betacheck

    if [ "$track" = "0" ]; then trackdisp="Stable"; else trackdisp="Beta"; fi

    clear
    echo -e "${InvGreen} ${InvDkGray}${CWhite} Update IOCMON                                                                                                                           ${CClear}"
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

    if [ "$track" = "0" ]; then
      remoteversion="$DLversion"; remotelabel="STABLE"; remoteurl="$iocmonrepostable/iocmon.sh"
    else
      remoteversion="$Bversion"; remotelabel="BETA"; remoteurl="$iocmonrepobeta/iocmon.sh"
    fi

    if [ -n "$remoteversion" ] && [ "$version" = "$remoteversion" ]; then
      echo -e "You are on the latest ${CGreen}${remotelabel}${CClear} version! Download & overwrite, or change tracks?"
    else
      echo -e "A new ${CGreen}${remotelabel}${CClear} version is available! Download & upgrade, or change tracks?"
    fi
    read -p "(Stable = 0, Beta = 1, Download = y/n, e=Exit): " selupdate
    case "$selupdate" in
      0) track=0; saveconfig ;;
      1) track=1; saveconfig ;;
      [Yy])
        echo ""
        echo -e "Downloading IOCMON ${CGreen}${remotelabel}${CClear}..."
        if curl --silent --retry 3 --connect-timeout 3 --max-time 10 --retry-delay 1 --retry-all-errors --fail "$remoteurl" -o "${apppath}.new"; then
          mv "${apppath}.new" "$apppath"
          chmod 755 "$apppath"
          echo -e "${CGreen}Download successful.${CClear}"
          echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - INFO: IOCMON updated to the $remotelabel track successfully." >> "$logfile"
          echo ""
          read -rsp $'Press any key to restart IOCMON...\n' -n1 key
          exec sh "$apppath" -noswitch
        else
          rm -f "${apppath}.new"
          echo -e "${CRed}ERROR: Download failed - check network connectivity and try again.${CClear}"
          echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - ERROR: IOCMON $remotelabel update download failed." >> "$logfile"
          echo ""
          read -rsp $'Press any key to continue...\n' -n1 key
        fi
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

  if [ ! -d /opt ]; then
    echo -e "${CRed}ERROR: Entware was not found on this router.${CClear}"
    echo -e "Please install Entware using the AMTM utility first, then return to this menu."
    echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - ERROR: Entware was not found installed on router. Please investigate." >> "$logfile"
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
    echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - INFO: Optional Entware package(s) installed: $pkgs" >> "$logfile"
    echo ""
    read -rsp $'Press any key to continue...\n' -n1 key
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# ventwarecomponents explains and optionally installs every Entware package IOCMON can use, all of them optional.

ventwarecomponents()
{
  local screenstatus findstatus jqstatus selentware

  while true; do
    clear
    if [ -x /opt/sbin/screen ]; then screenstatus="${CGreen}Installed${CClear}"; else screenstatus="${CYellow}Not installed${CClear}"; fi
    if [ -x /opt/bin/find ]; then findstatus="${CGreen}Installed${CClear}"; else findstatus="${CYellow}Not installed${CClear}"; fi
    if which jq >/dev/null 2>&1; then jqstatus="${CGreen}Installed${CClear}"; else jqstatus="${CYellow}Not installed${CClear}"; fi

    echo -e "${InvGreen} ${InvDkGray}${CWhite} Optional Entware Components                                                                                                             ${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} IOCMON runs fully in a reduced mode without any of these - each one only unlocks or${CClear}"
    echo -e "${InvGreen} ${CClear} speeds up one specific feature. All of this requires Entware itself, already installed${CClear}"
    echo -e "${InvGreen} ${CClear} via the AMTM utility.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(1)${CClear} : screen             : ${screenstatus}${CClear}"
    echo -e "${InvGreen} ${CClear}       Runs IOCMON continuously in the background so it survives an SSH disconnect and${CClear}"
    echo -e "${InvGreen} ${CClear}       can autostart on reboot. Required specifically for the -screen/autostart feature -${CClear}"
    echo -e "${InvGreen} ${CClear}       without it, IOCMON only runs in the foreground while you stay attached to it.${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(2)${CClear} : findutils          : ${findstatus}${CClear}"
    echo -e "${InvGreen} ${CClear}       Full GNU find, used by the filesystem-integrity scan. Without it, IOCMON falls${CClear}"
    echo -e "${InvGreen} ${CClear}       back to the router's own built-in BusyBox find automatically - scans still run${CClear}"
    echo -e "${InvGreen} ${CClear}       correctly either way, this only affects how efficiently they run.${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(3)${CClear} : jq                 : ${jqstatus}${CClear}"
    echo -e "${InvGreen} ${CClear}       Lets ThreatFox's authenticated API mode enrich detections with malware family/${CClear}"
    echo -e "${InvGreen} ${CClear}       confidence data. Without it, ThreatFox still works fully via its free CSV export -${CClear}"
    echo -e "${InvGreen} ${CClear}       you only lose that extra detail.${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(4)${CClear} : Install all of the above${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite} | ${CClear}"
    echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(e)${CClear} : Return to Configuration Menu${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
    echo ""
    read -p "Please select? (1-4, e=Exit): " selentware
    case "$selentware" in
      1) installentwarepkg "screen" ;;
      2) installentwarepkg "findutils" ;;
      3) installentwarepkg "jq" ;;
      4) installentwarepkg "screen findutils jq" ;;
      [Ee]) break ;;
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
  echo -e "${InvGreen} ${InvDkGray}${CWhite} Uninstall Utility                                                                                                                       ${CClear}"
  echo -e "${InvGreen} ${CClear}"
  echo -e "${InvGreen} ${CClear} This will remove IOCMON from your router: the script, its cron jobs, autostart hook,${CClear}"
  echo -e "${InvGreen} ${CClear} and its config/log directory. This action is irreversible.${CClear}"
  echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
  echo ""
  echo -e "Do you wish to proceed?"
  if promptyn "[y/n]: "; then
    echo ""
    echo -e "${CGreen}Removing scheduled cron jobs...${CClear}"
    cru d IOCMONUpdate >/dev/null 2>&1
    cru d IOCMONFeeds >/dev/null 2>&1
    cru d IOCMONFsIntegrity >/dev/null 2>&1

    if [ -f /jffs/scripts/services-start ]; then
      sed -i '/# iocmon-cron/d' /jffs/scripts/services-start
      sed -i '/# iocmon-autostart/d' /jffs/scripts/services-start
    fi
    if [ -f /jffs/scripts/post-mount ]; then
      sed -i '/# iocmon-autostart/d' /jffs/scripts/post-mount
    fi

    echo -e "${CGreen}Stopping any running IOCMON SCREEN session...${CClear}"
    if [ -x /opt/sbin/screen ]; then
      /opt/sbin/screen -S iocmon -X quit >/dev/null 2>&1
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

progresspromptactive=0
laststatustext=""
lastinputtext=""
driveunmountedalerted=0
dnsquerylogwarned=0
dnsquerymissingwarned=0
bypassscreentimer=0
conntrackchecked=0; conntracklastcheck=""
dnschecked=0; dnslastcheck=""
authchecked=0; authlastcheck=""
alertviewmode="ioc"
dnscheckpointcache=""; authcheckpointcache=""
timerpaused=0

# Remove Maintenance Mode file lock left over from a prior run
rm -f "$updatingfile" >/dev/null 2>&1

if [ ! -d "$addonsdir" ]; then
  mkdir -m 755 -p "$addonsdir"
fi

if [ "$1" = "amtmupdate" ]; then
    shift
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
if [ "$1" == "-h" ] || [ "$1" == "-help" ] || [ "$1" == "-setup" ] || [ "$1" == "-noswitch" ] || [ "$1" == "-autoupdate" ] || [ "$1" == "-email" ] || [ "$1" == "-screen" ] || [ "$1" == "-updatefeeds" ] || [ "$1" == "-fsintegrity" ]; then
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
    else
      initialsetup
    fi
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
    enablealertemail=1
    sendmessage 1 "test" "Test alert" "manual" "requested via -email switch"
    exit 0
fi

# Check to see if autoupdate is being called (cron-callable).
if [ "$1" == "-autoupdate" ]; then
    if [ ! -f "$config" ]; then
      echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - WARNING: Autoupdate skipped - IOCMON has not completed initial setup yet." >> "$logfile"
      exit 1
    fi
    . "$config"
    updatecheck
    betacheck
    if [ "$updateiocm" -eq 1 ]; then
      echo > "$updatingfile"
      ScriptUpdateFromAMTM
      rm -f "$updatingfile" >/dev/null 2>&1
    fi
    exit 0
fi

# Check to see if a one-shot feed refresh is being called (cron-callable via the IOCMONFeeds cru entry).
if [ "$1" == "-updatefeeds" ]; then
    if [ ! -f "$config" ]; then
      echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - WARNING: -updatefeeds skipped - IOCMON has not completed initial setup yet." >> "$logfile"
      exit 1
    fi
    . "$config"
    checkfeedupdate
    exit 0
fi

# Check to see if a one-shot filesystem-integrity check is being called (cron-callable via IOCMONF -fsintegrity)
if [ "$1" == "-fsintegrity" ]; then
    if [ ! -f "$config" ]; then
      echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - WARNING: -fsintegrity skipped - IOCMON has not completed initial setup yet." >> "$logfile"
      exit 1
    fi
    . "$config"
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
      echo -e "${CRed}ERROR: The Entware 'screen' package is required for -screen mode.${CClear}"
      echo -e "Install it with: opkg install screen"
      echo ""
      echo -e "${CClear}"
      exit 1
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
  if [ -n "$oldpid" ] && [ "$oldpid" != "$$" ] && kill -0 "$oldpid" 2>/dev/null; then
    echo -e "$(date +'%b %d %Y %X') $(nvram get lan_hostname) IOCMON[$$] - ERROR: Another IOCMON instance (PID $oldpid) is already running - exiting to avoid state corruption." >> "$logfile"
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
trap 'rm -f "$pidfile"' EXIT INT TERM

# Check for and add an alias for IOCMON
if ! grep -F "sh /jffs/scripts/iocmon.sh" /jffs/configs/profile.add >/dev/null 2>/dev/null; then
  echo "alias iocmon=\"sh /jffs/scripts/iocmon.sh\" # added by iocmon" >> /jffs/configs/profile.add
fi

# Grab the IOCMON config file and read it in, or run interactive first-time setup (including drive selection)
if [ -f "$config" ]; then
  . "$config"
else
  initialsetup
fi

# Check for updates
updatecheck
betacheck

# -------------------------------------------------------------------------------------------------------------------------
# renderdashboard paints the full main-screen dashboard from already-current state/globals

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
  if [ -n "$stateroot" ] && [ -f "$stateroot/alert_pending" ]; then
    echo -e "${InvGreen} ${CClear}"
    pendingcount="$(sed -n '1p' "$stateroot/alert_pending" 2>/dev/null)"
    pendingsummary="$(sed -n '2p' "$stateroot/alert_pending" 2>/dev/null)"
    [ "${#pendingsummary}" -gt 129 ] && pendingsummary="$(printf '%.128s' "$pendingsummary")>"
    echo -en "${InvRed}${CWhite} "; padright "!!! SECURITY ALERT: ${pendingcount:-1} unacknowledged IOC detection(s) !!!" 137; echo -e "${CClear}"
    echo -e " ${CWhite}Latest: ${pendingsummary:-see the IoC log}${CClear}"
    echo -en "${InvRed}${CWhite} "; padright "Press (A) to Acknowledge" 137; echo -e "${CClear}"
  fi

  if [ "$track" = "0" ] && [ "$UpdateNotify" != "0" ]; then
    echo -e "$UpdateNotify"
  fi
  if [ "$track" = "1" ] && [ "$BUpdateNotify" != "0" ]; then
    echo -e "$BUpdateNotify"
  fi

  echo -e "${InvGreen} ${CClear}"

  feedsindicatorcount=0
  feedsbreakdown=""
  feedsoldest="n/a"
  if [ -n "$feedsroot" ] && [ -f "$feedsroot/ips.txt" ]; then
    feedsindicatorcount="$(cat "$feedsroot/ips.txt" "$feedsroot/domains.txt" "$feedsroot/hashes.txt" 2>/dev/null | wc -l | tr -d ' ')"
    feedsbreakdown="$(feedsourcecounts | sed 's/ *$//')"
    feedsoldest="$(feedsoldestfetch)"
  fi

  dnsstatus="${CDkGray}off${CClear}"
  if [ "$enablednswatch" -eq 1 ]; then
    if dnsquerylogenabled; then dnsstatus="${CGreen}on${CClear} (${dnsqueriedcount:-0} queries checked, checked ${dnslastcheck:-n/a})"; else dnsstatus="${CYellow}on, awaiting query-log setup${CClear}"; fi
  fi
  conntrackstatus="${CDkGray}off${CClear}"
  [ "$enableconntrackwatch" -eq 1 ] && conntrackstatus="${CGreen}on${CClear} (${conntrackchecked} dst ips, checked ${conntracklastcheck:-n/a})"
  authstatus="${CDkGray}off${CClear}"
  [ "$enableauthwatch" -eq 1 ] && authstatus="${CGreen}on${CClear} (+${authchecked} new, checked ${authlastcheck:-n/a})"
  nvramstatus="${CDkGray}off${CClear}"
  [ "$enablenvramwatch" -eq 1 ] && nvramstatus="${CGreen}on${CClear} ($(echo "$nvramwatchvars" | wc -w | tr -d ' ') vars watched, checked ${nvramlastcheck:-n/a})"

  fsbaselinecount=0
  [ -n "$stateroot" ] && [ -f "$stateroot/fs_baseline.db" ] && fsbaselinecount="$(wc -l < "$stateroot/fs_baseline.db" | tr -d ' ')"
  fsstatus="${CDkGray}off${CClear}"
  if [ "$enablefsintegrity" -eq 1 ]; then
    if [ -n "$stateroot" ] && [ -f "$stateroot/fs_baseline.db" ]; then
      fsstatus="${CGreen}on${CClear} ($fsbaselinecount files baselined)"
    else
      fsstatus="${CYellow}on, no baseline yet${CClear}"
    fi
  fi

  lastalert="$(lastalertsummary)"
  todaycount="$(alertstoday)"

  if [ "$enablealertemail" = "1" ]; then
    amtmdisp="${CGreen}On${CClear}"
  else
    amtmdisp="${CDkGray}Off${CClear}"
  fi
  rldisp="${CGreen}unlimited${CClear}"
  [ "$ratelimit" != "0" ] && rldisp="${CGreen}${ratelimit}/h${CClear}"

  cronstatus="${CDkGray}not scheduled${CClear}"
  which cru >/dev/null 2>&1 && cru l 2>/dev/null | grep -q "IOCMONFeeds" && cronstatus="${CGreen}scheduled${CClear}"

  routermodel="$(nvram get odmpid)"
  [ -z "$routermodel" ] && routermodel="$(nvram get productid)"
  routeruptime="$(uptime 2>/dev/null | sed -E 's/^[^,]*up[[:space:]]*//; s/,[[:space:]]*[0-9]+ users?.*//')"
  drivefreespace="n/a"
  [ -n "$iocmonroot" ] && drivefreespace="$(df -h "$iocmonroot" 2>/dev/null | awk 'NR==2{print $4}')"
  [ -z "$drivefreespace" ] && drivefreespace="n/a"

  echo -en "${InvGreen} ${CClear} "; padright "Feeds: ${CGreen}${feedsindicatorcount}${CClear} loaded, every ${CGreen}${feedupdatehrs}h${CClear}, oldest ${CGreen}${feedsoldest}${CClear}" 75; echo -e "Alerts Today: ${CGreen}${todaycount}${CClear}"
  [ "${#lastalert}" -gt 49 ] && lastalert="$(printf '%.48s' "$lastalert")>"
  echo -en "${InvGreen} ${CClear} "; padright "  Sources: ${CGreen}${feedsbreakdown:-none}${CClear}" 75; echo -e "Last Alert: ${CGreen}${lastalert}${CClear}"
  echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
  echo -en "${InvGreen} ${CClear} "; padright "conntrack: $conntrackstatus" 75; echo -e "dns: $dnsstatus"
  echo -en "${InvGreen} ${CClear} "; padright "auth: $authstatus" 75; echo -e "fs-integrity: $fsstatus"
  echo -e "${InvGreen} ${CClear} nvram: $nvramstatus"
  echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
  echo -en "${InvGreen} ${CClear} "; padright "Email: $amtmdisp (limit: $rldisp)" 75; echo -e "Cron: $cronstatus"
  echo -en "${InvGreen} ${CClear} "; padright "Router: ${CGreen}${routermodel:-unknown}${CClear} ($(nvram get lan_hostname))" 75; echo -e "Storage: $drivestatus"
  echo -en "${InvGreen} ${CClear} "; padright "${CDkGray}${routeruptime}${CClear}" 75; echo -e "Drive free: ${CGreen}${drivefreespace}${CClear}"
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
    echo -e "${InvGreen} ${CClear} ${CWhite}Recent Dropbear Attempts${CClear} (kept to the last ${CGreen}${logsize}${CClear} lines - press [${CGreen}V${CClear}] to view the full log, or [${CGreen}O${CClear}] for IoC Detections)"
    if [ -s "$dropbearlogfile" ]; then
      tail -n 10 "$dropbearlogfile" | while IFS= read -r dbline; do
        [ "${#dbline}" -gt 134 ] && dbline="$(printf '%.133s' "$dbline")>"
        echo -e "${InvGreen} ${CClear}   ${CYellow}${dbline}${CClear}"
      done
    else
      echo -e "${InvGreen} ${CClear}   ${CDkGray}No dropbear login-failure attempts logged yet.${CClear}"
    fi
  else
    echo -e "${InvGreen} ${CClear} ${CWhite}Recent IoC Detections${CClear} (kept indefinitely - press [${CGreen}V${CClear}] to view the full log, or [${CGreen}D${CClear}] for Dropbear attempts)"
    if [ -n "$stateroot" ] && [ -s "$stateroot/ioc_alerts.log" ]; then
      tail -n 10 "$stateroot/ioc_alerts.log" | while IFS= read -r iocline; do
        [ "${#iocline}" -gt 134 ] && iocline="$(printf '%.133s' "$iocline")>"
        echo -e "${InvGreen} ${CClear}   ${CGreen}${iocline}${CClear}"
      done
    else
      echo -e "${InvGreen} ${CClear}   ${CDkGray}No detections logged yet. Press (T) to simulate one and confirm alerting works.${CClear}"
    fi
  fi
  echo -e "${InvGreen} ${CClear}${CDkGray}-----------------------------------------------------------------------------------------------------------------------------------------${CClear}"
  echo ""
}

while true; do
  clear
  echo -e "${CGreen}IOCMON v$version [Scanning for IoC's ... Please stand by]${CClear}"

  if [ -f "$config" ]; then
    . "$config"
  else
    initialsetup
  fi

  checkdrivealive
  checkfeedupdate

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
    if dnsquerylogenabled; then
      echo -e "  ${CGreen}*${CClear} Checked ${CGreen}${dnsqueriedcount}${CClear} DNS domain lookup(s) against known-malicious-domain feeds"
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
    echo -e "  ${CGreen}*${CClear} Checked ${CGreen}$(echo "$nvramwatchvars" | wc -w | tr -d ' ')${CClear} security-relevant NVRAM variable(s) (SSH/Telnet, WAN DNS, WAN type, JFFS scripts) for unexpected changes"
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

  timer=0
  while [ "$timer" -lt "$timerloop" ]; do
    [ "$timerpaused" -ne 1 ] && timer="$((timer+1))"
    preparebar 46 "|"
    progressbaroverride "$timer" "$timerloop" "" "s" "Standard"
    [ -f "$updatingfile" ] && break
  done

done

exit 0

