# IOCMON v1.2.7
Asus-Merlin IDS/IPS Security Intelligence Monitor

Modified: Oct-15-2026

> **License:** GPLv3 with additional terms (§7c/§7e) — see [`NOTICE.md`](./NOTICE.md). The code is free to fork and modify; the name **IOCMON** is reserved for this project — see [`TRADEMARK.md`](./TRADEMARK.md) before publishing a rebrand or fork.

-----

<img width="1251" height="670" alt="image" src="https://github.com/user-attachments/assets/20d3a012-792e-4bdd-8540-fadb282bb09d" />

-----
# IOCMON — User Manual

## What is IOCMON?

IOCMON is a lightweight, always-on IDS/IPS security-intelligence monitor for Asus-Merlin routers. It runs
quietly in the background and watches your router from four different angles at once, correlating what it
sees against public threat-intelligence feeds to catch signs of compromise early, before they become a real
problem.

**Why run it:**

- **No extra hardware, no cloud dependency.** IOCMON runs entirely on your router (plus an optional USB drive
  for feed/state storage) — nothing leaves your network except the periodic, read-only feed downloads.
- **Correlates real threat intelligence**, not just generic anomaly noise. Every alert is checked against
  live indicator feeds from Feodo Tracker, Spamhaus, URLhaus, and ThreatFox before it's raised.
- **Watches the whole picture, not just one thing:**
  - **Network traffic** — active connections and DNS lookups checked against known-malicious IPs/domains.
  - **Filesystem integrity** — new, modified, deleted, and permission-escalated files across any folders you
    choose, plus automatic hash-matching against known malware signatures.
  - **Brute-force logins** — both a sudden burst of failed dropbear/httpd logins and a slow, sustained attempt
    that stays under the radar of a simple threshold.
  - **Router configuration tampering** — unexpected changes to security-relevant NVRAM settings (SSH/Telnet
    exposure, WAN DNS), new port-forward/DMZ/UPnP rules, and unauthorized new cron jobs.
- **Tells you what changed, not just that something did.** New/modified/deleted/permission-changed files are
  each logged by name and timestamp, not just a bare count.
- **Optional automatic quarantine** for any file that matches a known-malware hash — strips the execute bit
  and renames it, never deletes, so nothing is lost by mistake.
- **Email alerts via AMTM**, batched into a single email when several things fire in the same cycle instead of
  flooding your inbox.
- **Built to avoid false-alarm fatigue**: exception lists for DNS domains and cron jobs, folder/extension/file
  exclusions for the filesystem watch, and a dedicated dashboard showing exactly what's configured and why.
- **Everything is visible on one screen** — a live dashboard shows feed freshness, per-watch activity, recent
  detections, and system status at a glance, with simple single-key shortcuts for every common action.

---

## Getting Started

### 1. Installation

Run from an SSH prompt on your router:
```
curl -fsSL "https://github.com/ViktorJp/IOCMON/releases/latest/download/iocmon.sh" -o "/jffs/scripts/iocmon.sh" && chmod 755 "/jffs/scripts/iocmon.sh"
```

Or, copy `iocmon.sh` to `/jffs/scripts/iocmon.sh` on your router and make it executable:

```
chmod +x /jffs/scripts/iocmon.sh
```

### 2. First run — initial setup

Run the script for the first time:

```
sh /jffs/scripts/iocmon.sh -setup
```

The first time IOCMON runs with no existing config, it walks you through a short setup wizard:

- **Feed storage location.** IOCMON needs a place to store its threat-intelligence feed data and detection
  history. If you have a USB drive already mounted (the common case), IOCMON detects it automatically — confirm
  it if only one is found, or pick from a numbered list if you have more than one. If no drive is available,
  you can proceed in a reduced **degraded mode** (JFFS-only storage, a smaller feed set) instead.
- Once a drive is selected (or degraded mode is confirmed), IOCMON writes its default configuration and you're
  dropped into the **Initial Scan**.

### 3. Start the background monitor

Network/log-based detection (connections, DNS, logins, NVRAM) only runs while IOCMON's monitor loop is
actually running — it's not something cron alone can do. Launch it in a persistent background SCREEN session:

```
sh /jffs/scripts/iocmon.sh -screen -now
```

To have it start automatically on every reboot, turn on **Autostart** in Advanced Settings → General / Script
Behavior (see below). This hooks the router's `post-mount` script so it launches once the USB drive is ready.

Two periodic tasks (feed refresh and filesystem-integrity scans) are scheduled via cron automatically whenever
you save any setting, and run on their own independent of whether the background monitor is up — but for
real-time detection of network traffic, DNS lookups, login attempts, and NVRAM changes, the background monitor
needs to actually be running.

### 4. Reattach to the live dashboard any time

```
sh /jffs/scripts/iocmon.sh -screen
```

or just type `iocmon` if you've used the shell alias IOCMON registers automatically.

---

## The Main Dashboard

Once running, the main screen shows: feed status and per-source counts, each watch's on/off state and most
recent activity, the filesystem-integrity summary (with direct shortcuts to the new/modified/deleted/
permission-change file lists), router/storage stats, and a running countdown to the next check cycle. A red
banner takes over the top of the screen whenever a real detection is pending, until acknowledged.

**Hotkeys** (press the letter, no Enter needed):

| Key | Action |
|---|---|
| `c` | Open the Configuration Menu |
| `f` | Force an immediate IoC feed refresh |
| `i` | Force an immediate filesystem-integrity scan |
| `1`–`4` | View the New / Modified / Deleted / Permission-changed file list from the last scan |
| `v` | View the full detection log (or the dropbear-attempt log — see `d`/`o` below) |
| `d` | Switch the "Recent" panel and `v` to show dropbear login attempts |
| `o` | Switch the "Recent" panel and `v` back to IoC detections |
| `h` | Switch the "Recent" panel and `v` to the hash-check log |
| `z` | IoC Detections panel only: add a numbered `dns` entry's base domain to the DNS Exceptions list |
| `n` | IoC Detections panel only: show a quick OTX AlienVault Threat Report (last 7 days, sorted by date, 20 per page); any key returns to the main screen |
| `r` | Clear whichever log the "Recent" panel is currently showing (asks for confirmation first) |
| `r!` | Instantly clears that same log with no confirmation — type both characters, then Enter |
| `t` | Simulate a detection end-to-end (using a real, currently-loaded feed indicator) to confirm alerting works |
| `a` | Acknowledge the red alert banner |
| `p` | Pause/resume the countdown — while paused, you can browse any menu and return without triggering a rescan |
| `x` | Detach from the background SCREEN session (also resumes the countdown if it was paused) |
| `l` | View the raw activity log |
| `e` | Exit — asks "Are you sure you wish to Exit" first, since `e` is easy to hit by mistake when you meant `x` |

---

## Configuring IOCMON to Do What You Want

Everything is reachable from the **Configuration Menu** (`c` from the main screen, or `iocmon -setup`):

| Item | Purpose |
|---|---|
| (1) Select Feed Storage Location | Re-run drive selection if your USB drive changes |
| (2) Select Feed Sources & API Keys | Turn feed sources on/off, set a ThreatFox API key, set feed refresh cadence |
| (3) Force IoC Threat Feed Refresh | Refresh feeds immediately (also available as `f` on the main screen) |
| (4) Force Filesystem-Integrity Scan | Run a scan immediately (also available as `i` on the main screen) |
| (5) OTX AlienVault Threat Report | Build a date-ranged report of outbound threat-feed matches, each with a ready-made AlienVault OTX lookup link (see **The OTX AlienVault Threat Report**, below) |
| (6) Reset IOCMON back to Default Settings | Erase all customization and start fresh (see **Starting Over**, below) |
| (7) Import/Export IOCMON Settings | Save your configuration to a portable file, or load one from elsewhere (see **Importing/Exporting Settings**, below) |
| (8) Update IOCMON to Latest Version | Check for and install a newer Stable or Beta build |
| (9) Optional Entware Components | Install `screen`/`findutils`/`jq`, needed for a few optional features |
| (10) Advanced Settings | Every detection toggle and threshold — see the six submenus below |
| (11) Uninstall IOCMON | Fully remove IOCMON from the router |

### Optional: Q-Feeds (larger OSINT lists)

Under **Select Feed Sources & API Keys** you can turn on **Q-Feeds**, which adds a large list of malicious IPs
and domains (a few hundred thousand entries). It is off by default. Create a free Community account and API
token at tip.qfeeds.com, enter it under *Q-Feeds API Key*, then switch Q-Feeds on. The lists are downloaded
about once a day (adjustable under *Q-Feeds refresh*) and stored on your USB drive; they are not available in
the reduced JFFS-only mode. Alerts from this source read `qfeeds` / `osint-ip` or `osint-domain`.

### Advanced Settings, by what you're trying to achieve

**"I want to control email alerts"** → *Alerting & Notifications*
Turn alert emails on/off, and cap how many can send per hour (0 = unlimited) — useful if you're worried about
a noisy detection flooding your inbox. Choose whether the on-screen SECURITY ALERT banner appears at the top
of the dashboard (default) or just above the timer/hotkey line at the bottom. Choose whether the banner and
email fire for every detection (default) or only for ones that match a real IoC feed indicator — the quieter
setting skips heuristic/behavioral detections (DNS tunneling, brute-force, cron/config/NVRAM changes, new
executables) for the banner and email, while every detection still appears in the "Recent IoC Detections" log.

**"I want to watch DNS lookups against known-bad domains, or catch DNS tunneling"** → *DNS Watch & Tunneling
Detection*
Turn on feed-based DNS matching (this also offers to enable the router's own dnsmasq query logging, which it
needs to see anything). Turning the DNS watch back off removes that query-logging line and restarts dnsmasq,
so the router stops logging every lookup. IOCMON finds where dnsmasq's queries are written automatically
(normal syslog, a `log-facility=` file, or a syslog-ng/scribe `dnsmasq.log`); if your setup routes them somewhere
it can't detect, set the file path yourself under *DNS query log file*. Add domains to the exceptions list for known false positives (e.g. a CDN flagged only
because a malicious URL was once hosted there). Separately, turn on the behavioral tunneling/exfiltration
heuristic if you want to catch unusually long or high-volume DNS query patterns — this is off by default since
it can false-positive against legitimate high-subdomain-churn services; the same exceptions list quiets it too.

**"I want to catch brute-force login attempts"** → *Brute-Force Login Detection*
Two independent layers: a **burst** alert (N failed logins from one IP within a single check) and a
**sustained** alert (N failed logins from one IP across a longer sliding window, for an attacker deliberately
staying under the burst threshold). Tune both thresholds and the sustained window size here.

**"I want to watch files/folders for tampering"** → *Filesystem Integrity & Cron Watch*
This is the largest section — how often to scan, which folders to watch, and four ways to exclude noise:
folder names, file extensions, individual files by absolute path, and (further down) cron jobs known to be
re-added legitimately by another tool. Also controls the hash-size cap, automatic quarantine on a malware-hash
match, deletion alerts on critical paths, permission-escalation alerts, and the cron-tampering diff itself.
See **Reducing False Positives**, below, for the exclusion mechanisms specifically.

**"I want to watch the router's own configuration for tampering"** → *Network & System Watches*
Watch live connections against known-malicious IPs, watch a curated list of security-relevant NVRAM settings
(SSH/Telnet exposure, WAN DNS), and alert on unexpected new port-forward/DMZ/UPnP rules. If a specific IP or
CIDR range keeps matching a feed and you know it's safe, add it to the IP/CIDR Exceptions list (item 4) — unlike
the watched/excluded folder lists under Filesystem Integrity, this is single IPs or ranges (e.g. `204.44.63.22`
or `204.44.0.0/16`), not a hostname, and it's checked before the connection is ever compared to a feed.

**"I want to change how often it checks, how much it logs, or how it updates itself"** → *General / Script
Behavior*
Main loop interval, log size cap, where the activity log lives, whether to autostart on reboot, IOCMON's own
self-update schedule/track.

The activity log (`iocmon.log`) is kept on JFFS (`/jffs/addons/iocmon.d/iocmon.log`) by default. Item (3) moves it to
the external drive instead (`/tmp/mnt/<drive>/iocmon.d/state/iocmon.log`) to spare the router's flash from constant
log writes. Pressing it again moves it back. Both directions ask for confirmation and carry the existing log over.
If the drive is ever missing, IOCMON logs to JFFS temporarily and merges those lines back once the drive returns.

### Reducing False Positives

If a legitimate service, file, or scheduled task keeps triggering alerts, IOCMON has a purpose-built exception
list for nearly every watch instead of forcing you to disable the whole feature:

- **DNS**: add the domain to the DNS exceptions list (DNS Watch & Tunneling Detection → item 2).
- **Filesystem — a whole folder**: add its name to the excluded-folder-names list (item 4). Matches the name
  anywhere it appears under a watched tree.
- **Filesystem — a file type**: add the extension to the excluded-extensions list (item 5), e.g. `.log`.
- **Filesystem — one specific file**: add its full path to the excluded-files list (item 6).
- **Connections — one IP or range**: add it to the IP/CIDR Exceptions list (Network & System Watches → item 4).
- **Cron**: use the cron exceptions picker (item 12) to select a specific job from a live numbered list rather
  than retyping it by hand — this survives a managing tool later re-writing that job's own schedule.

### The OTX AlienVault Threat Report

**Configuration Menu → (5) OTX AlienVault Threat Report** builds a ranked list of the external IP addresses
IOCMON's conntrack watch has caught a device on your network contacting that match a known-bad threat-feed
indicator, over whatever date range you choose. For each matched IP it shows how many separate alerts IOCMON
logged for it, which feed(s)/malware family flagged it, which local device(s) on your network reached out to
it, and a ready-made `https://otx.alienvault.com/indicator/ip/<ip>` link you can open to look it up on
AlienVault's free OTX reputation service.

Item (6) on the report's own menu toggles the sort order between **Frequency** (one row per matched IP, most
alerts first — the default) and **Date** (every individual alert occurrence listed separately, newest first, with
its own date/time and the local device involved). Your choice is saved and used for every later run.

Pick a date range (today, last 7/30 days, all available history, or a custom start/end date), then how many
rows to show per page (10/20/50). The report's header also shows how many days of detection history are
currently available in the log, so you can judge how much a given range actually covers. If the result spans
more than one page, press Enter for the next page, `a` to show every remaining row at once, or `e` to return
to the report's own date-range menu. Any "press any key" prompt also returns you to that same date-range menu
rather than leaving the report entirely — use `e`/`e!` on the date-range screen itself to go back to the
Configuration Menu.

Two things worth knowing about what the numbers mean: the count is how many distinct alert *events* IOCMON
actually logged for that IP — not a raw packet/connection counter the way a firewall's own ban-list statistics
are, since repeated hits on the same IP within IOCMON's own 6-hour dedup window only ever log once — so treat
it as a frequency indicator, not an exact tally. And this report only ever covers *outbound* matches (a device
here reaching out to a listed bad IP) — IOCMON's conntrack watch has no way to see unsolicited inbound traffic
that a listed bad IP sends toward your router.

### Importing/Exporting Settings

**Configuration Menu → (7) Import/Export IOCMON Settings** lets you carry your configuration — every toggle,
threshold, and exclusion list — between routers, or keep a backup before experimenting:

- **Export** writes your current settings to a plain `.ioc` file, defaulting to `<your-router's-hostname>-
  config-export.ioc` on your feed storage drive (you can type a different path/filename instead). It asks
  separately whether to include your ThreatFox/Q-Feeds API keys — leave them out if you plan to share or store
  the file somewhere less trusted, and just re-enter them afterward under Select Feed Sources & API Keys.
- **Import** loads a `.ioc` file and overwrites your current configuration with it, then restarts IOCMON. Your
  feed storage drive selection is always kept as this router's own — it's never overwritten by the import file.
  Any watched-folder path tied to the *old* router's drive label is automatically updated to this router's own
  label, and a manually-set DNS query log path is reset to auto-detect, since both are specific to the router
  that originally saved them.
- You can also import a `.ioc` file during first-time setup, right after selecting your feed storage drive — if
  you have one, this replaces the rest of the setup wizard with your imported settings instead.

### Starting Over

If your configuration has drifted somewhere you don't want, use **Configuration Menu → (6) Reset IOCMON back
to Default Settings**. After a confirmation prompt explaining exactly what will happen, this erases the saved
config and restarts IOCMON fresh — every toggle, threshold, and list reverts to its shipped default, and you'll
be walked back through the initial drive-selection setup. This cannot be undone.

### Uninstalling

**Configuration Menu → (11) Uninstall IOCMON** removes the script, its cron jobs, its autostart hook, the
background SCREEN session, and the shell alias. After a second, separate confirmation, it also removes the
feed/state data from your USB drive. This is irreversible.

### Support and Discussion Forum

Full support of this script is available on SNB Forums: 
https://www.snbforums.com/threads/97925/
