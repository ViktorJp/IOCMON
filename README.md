# IOCMON v2.1.3 BETA
Asus-Merlin IDS/IPS Security Intelligence Monitor

Modified: Nov-27-2026

> **License:** GPLv3 with additional terms (§7c/§7e) — see [`NOTICE.md`](./NOTICE.md). The code is free to fork and modify; the name **IOCMON** is reserved for this project — see [`TRADEMARK.md`](./TRADEMARK.md) before publishing a rebrand or fork.

-----

Terminal Interface:
<img width="1251" height="607" alt="image" src="https://github.com/user-attachments/assets/0b59d60b-e256-4e1a-b359-a0416f744e65" />

-----

Router Web UI:

<img width="789" height="717" alt="image" src="https://github.com/user-attachments/assets/8ac49f2e-3fdb-410c-be1e-49a7f246ff53" />
<img width="790" height="603" alt="image" src="https://github.com/user-attachments/assets/bebba7fb-5bd4-4993-b9ed-989c3512621c" />
<img width="788" height="661" alt="image" src="https://github.com/user-attachments/assets/e022a417-9782-4d61-98b5-4567db8c4594" />
<img width="790" height="253" alt="image" src="https://github.com/user-attachments/assets/9734d1e7-2a9d-4005-8e8f-f1f038b9c621" />

-----

Threat View:

<img width="680" height="731" alt="image" src="https://github.com/user-attachments/assets/7091406e-8e75-4fc5-9bb6-896de8a9d8d4" />

-----
# IOCMON — User Manual

## What is IOCMON?

IOCMON is a lightweight, always-on security-intelligence monitor for Asus-Merlin routers. It runs quietly in
the background and watches your router from four different angles at once, correlating what it sees against
public threat-intelligence feeds to catch signs of compromise early — before they become a real problem.

**Why run it:**

- **No extra hardware, no cloud dependency.** IOCMON runs entirely on your router (plus an optional USB drive
  for feed/state storage) — nothing leaves your network except the periodic, read-only feed downloads.
- **Correlates real threat intelligence**, not just generic anomaly noise. Every alert is checked against
  live indicator feeds from Feodo Tracker, Spamhaus, NetAPI.com, URLhaus, and ThreatFox before it's raised.
- **Watches the whole picture, not just one thing:**
  - **Network traffic** — active connections and DNS lookups checked against known-malicious IPs/domains. Lookups
    are read from the router's dnsmasq, or from AdGuard Home, Pi-hole or Technitium DNS Server.
  - **Filesystem integrity** — new, modified, deleted, and permission-escalated files across any folders you
    choose, plus automatic hash-matching against known malware signatures.
  - **Brute-force logins** — both a sudden burst of failed dropbear/httpd logins and a slow, sustained attempt
    that stays under the radar of a simple threshold. Failed router web logins and SSH logins for user names that
    don't exist both count.
  - **Router configuration tampering** — unexpected changes to security-relevant NVRAM settings (SSH/Telnet
    exposure, WAN DNS), new port-forward/DMZ/UPnP rules, and unauthorized new cron jobs.
- **Tells you what changed, not just that something did.** New/modified/deleted/permission-changed files are
  each logged by name and timestamp, not just a bare count.
- **Optional automatic quarantine** for any file that matches a known-malware hash — strips the execute bit
  and renames it, never deletes, so nothing is lost by mistake.
- **Email alerts via AMTM**, batched into a single email when several things fire in the same cycle instead of
  flooding your inbox. If an alert email is rejected (some mail providers refuse mail naming a flagged domain),
  IOCMON sends a short notice without the indicators instead. If mail can't be sent at all, the alerts are kept
  and retried every 10 minutes, up to 6 attempts.
- **Built to avoid false-alarm fatigue**: exception lists for DNS domains and cron jobs, folder/extension/file
  exclusions for the filesystem watch, and a dedicated dashboard showing exactly what's configured and why.
  Feed entries in loopback, private, CGNAT, multicast and other reserved ranges are dropped (and logged), since
  they can't name a remote host and would only match your own traffic or block your own network in Skynet.
- **Everything is visible on one screen** — a live dashboard shows feed freshness, per-watch activity, recent
  detections, and system status at a glance, with simple single-key shortcuts for every common action.

---

## Getting Started

### 1. Installation

Copy `iocmon.sh` to `/jffs/scripts/iocmon.sh` on your router and make it executable:

```
chmod +x /jffs/scripts/iocmon.sh
```

IOCMON requires Entware's `timeout` command (package `coreutils-timeout`). On some firmware builds an `nvram` or `cru`
call can hang and never return; IOCMON runs every such call through `timeout`, which stops it after 10 seconds, and
then reuses the last value it read for that setting. If `timeout` is missing when IOCMON starts (the monitor or
`-setup`, directly or under SCREEN), it asks whether to install it with `opkg`: type y or n and press Enter while a
60-second countdown runs. When the countdown ends without an answer, or if you decline, IOCMON
carries on without it, logs a warning, and asks again at the next start. It can also be installed at any time from
Configuration Menu item 9, Optional Entware Components (item 4).

## Release signing

  Every release of `iocmon.sh` and `iocmon.asp` is signed (ECDSA P-256, SHA-256). IOCMON checks each update against the
  key built into the copy you already run, and shows the result on its dashboard as
  `IOCMON Authenticity: script [ok] | web ui [ok]`.

  Release key fingerprint (SHA-256 of the public key):

  ```
  9165994b1eaaee8b6875a0109a4986eb90923fb64887ca486862d2e44f7f37bf
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
  you can proceed in a reduced **degraded mode** (JFFS-only storage, a smaller feed set) instead. In this mode
  the filesystem watch covers only the JFFS folders: the bare `/tmp/mnt/` entry in the watched-folder list is
  skipped, so other drives are never scanned into flash. IOCMON checks every cycle that the chosen drive is
  mounted and can be written. If the router has remounted it read-only (usually after a drive or filesystem
  error), IOCMON keeps matching connections and DNS lookups against the feeds already on the drive, but pauses
  feed updates, file integrity scans and alert history. If the drive is missing, feed matching pauses too. Either
  way IOCMON logs one ERROR, shows a red STORAGE WARNING banner and a red Storage value on the dashboard and the
  web page, and moves its activity log to JFFS until the drive is back. Repeat alerts are still held back for 6
  hours, using a record kept in RAM. Repair a read-only drive with a filesystem check (AMTM's disk check) or
  replace it; IOCMON resumes by itself and logs an INFO line. With alert email on, IOCMON also sends one email
  when the drive becomes read-only or unavailable, and another when it is writable again.
- **Import settings (optional).** You can load a `.ioc` export from a previous installation. If you do, setup
  skips the settings question below and goes straight to the web interface question.
- **Default settings or all functionality.** The default (recommended) keeps the shipped settings: only
  Critical alerts raise the banner and an email, and the detections most likely to cause noise stay off.
  **Enable all** also sets the alert level to All and switches on DNS watch, the DNS tunneling heuristic,
  permission-change watch and quarantine. DNS watch turns on dnsmasq query logging (`log-queries` in
  `dnsmasq.conf.add`) and restarts dnsmasq, unless AdGuard Home answers DNS, in which case add its login at
  Advanced Settings → DNS Watch, item 12. Skynet import, autostart and auto-update stay off either way.
- **API keys.** A short note lists the optional services that need a free API key (URLhaus and ThreatFox
  through one abuse.ch Auth-Key, Q-Feeds and AbuseIPDB) and where to get them. Setup doesn't ask for keys:
  enter them later under Configuration Menu item 2.
- **Web interface.** Answer `y` to add the IOCMON tab under the router's Addons menu right away. If the
  firmware has no add-on support or the page can't be downloaded, setup says so, leaves it off and carries
  on; you can turn it on later under Advanced Settings → General / Script Behavior, item 9.
- IOCMON then saves its configuration. Run with `-setup`, it opens the **Configuration Menu**; started as the
  monitor (`sh /jffs/scripts/iocmon.sh` or `-screen`), it downloads its first threat feeds and starts scanning.

### 3. Start the background monitor

Network/log-based detection (connections, DNS, logins, NVRAM) only runs while IOCMON's monitor loop is
actually running — it's not something cron alone can do. Launch it in a persistent background SCREEN session:

```
sh /jffs/scripts/iocmon.sh -screen -now
```

To have it start automatically on every reboot, turn on **Autostart** in Advanced Settings → General / Script
Behavior (see below) — this hooks the router's `post-mount` script so it launches once the USB drive is ready.

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

**Device names.** Connection and DNS alerts name the local device when the router knows it, for example
`192.168.1.169 [Living-Room-TV]->www.youtube.com`, wired and wireless alike. The name is the one you gave the device in the
router's client list, otherwise its DHCP reservation name, the name the router's network map found, or its DHCP hostname.
It is saved with the alert, so the log, emails, the web page (and its CSV `client_name` column) and Threat View's feed
show the name the device had at the time. Exceptions, the OTX report and repeat-alert checks still go by address only.

**IOCMON Authenticity.** Beside Filesystem Integrity, the dashboard shows whether this copy of IOCMON is genuine:
`IOCMON Authenticity: script [ok] | web ui [ok]`, with the signing date and key below it. Each release of `iocmon.sh` and
`iocmon.asp` carries a digital signature at the end of the file, made with the author's private key; IOCMON checks it with the
public key built into the copy you already run, using the router's own `openssl`.

| Word | Meaning |
|---|---|
| `ok` (green) | The signature matches: this is the file the author released, unchanged. |
| `invalid` (red) | A signature is there but doesn't match: the file was changed after release. |
| `unsigned` (red) | No signature at all, for example a copy put on the router by hand or a fork. |
| `restored` (red) | Since IOCMON last started, an altered copy of the script was found and replaced with the last verified copy. |
| `unchecked` (yellow) | No `openssl` on the router to check with. |
| `no key` / `off` (gray) | A copy from before signing began, or the web interface is off. |

While the script or page is `invalid` or `unsigned`, a red **AUTHENTICITY WARNING** banner stays on the dashboard and the web
page. It can't be acknowledged; it clears once a correctly signed copy is installed. Each such copy also raises one Critical
alert and email.

**An altered script is put back automatically.** If the installed `iocmon.sh` has been changed since it was signed, IOCMON replaces
it with the last verified copy (`/jffs/addons/iocmon.d/iocmon.sh.verified`) and restarts into it, so **any edits to the file are
undone**. The log and the alert email say so, and the dashboard shows a red banner naming when it happened. Press (A), or
Acknowledge on the web page, to clear the banner. The Authenticity line keeps showing `script [restored]` as a reminder until
IOCMON is restarted (stopped and started again, or the router rebooted); IOCMON restarting itself into the verified copy or into an
update doesn't count. A copy with no signature at all is not replaced: it shows `unsigned` with the warning above.

Updates are checked before they run:
- **Configuration Menu (8), the web page's Install Update and `-autoupdate`:** a download with a signature that doesn't match is
  refused and the installed version stays. A download with no signature is installed, with the warning.
- **AMTM:** AMTM writes the new file over the old one. The copy you were running then checks it, and puts the last verified
  copy (`/jffs/addons/iocmon.d/iocmon.sh.verified`) back if the signature doesn't match.
- **A file replaced by other means** while the monitor runs is checked the same way before IOCMON restarts into it, and the
  last verified copy is put back if it doesn't match.
- Each of these replacements shows the `restored` banner and status. After an AMTM update while IOCMON isn't running, they
  appear when IOCMON next starts.
- **The web page:** a downloaded page with a signature that doesn't match is refused and the old page kept.
- `-autoupdate` never installs an older version. Going back to an older version is still possible from Configuration Menu (8).

Astraea also reads these signatures and shows IOCMON as signed. The key's fingerprint is published on the IOCMON GitHub
page. Note that a copy changed on purpose could also remove its own warning, so the checks that count are the ones the
installed copy makes before a new one runs, and Astraea's independent check.

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
| `u` | Switch the "Recent" panel and `v` to the AbuseIPDB reputation log |
| `z` | IoC Detections panel only: add a numbered `dns` entry's base domain to the DNS Exceptions list |
| `n` | IoC Detections panel only: show a quick OTX AlienVault Threat Report (last 7 days, sorted by date, 20 per page); any key returns to the main screen |
| `r` | Clear whichever log the "Recent" panel is currently showing (asks for confirmation first) |
| `r!` | Instantly clears that same log with no confirmation — type both characters, then Enter |
| `t` | Simulate a detection end-to-end (using a real, currently-loaded feed indicator) to confirm alerting works — including a live AbuseIPDB reputation lookup when that check is on |
| `a` | Acknowledge the red alert banner |
| `p` | Pause/resume the countdown — while paused, you can browse any menu and return without triggering a rescan |
| `e` | Exit the SCREEN window (detach), leaving IOCMON running in the background (also resumes the countdown if it was paused) |
| `l` | View the raw activity log |
| `x` | Exit IOCMON — asks "Are you sure you wish to Exit" first, since `x` is easy to hit by mistake when you meant `e` |

Inside the Configuration Menu and its submenus, `e` returns one level up as usual, but typing `e!` and Enter
exits every menu at once, back to the main dashboard — settings are saved the same way either way. Ctrl-C quits
IOCMON from anywhere, menus included, and removes its lock file.

---

## Configuring IOCMON to Do What You Want

Everything is reachable from the **Configuration Menu** (`c` from the main screen, or `iocmon -setup`):

| Item | Purpose |
|---|---|
| (1) Select Feed Storage Location | Re-run drive selection if your USB drive changes |
| (2) Select Feed Sources, Reputation, API Keys and Lookups | Turn feed sources on/off, set the URLhaus/ThreatFox/Q-Feeds/AbuseIPDB API keys, set feed refresh cadence, configure the AbuseIPDB reputation check, and look up any IP or domain in the feeds (L) |
| (3) Force IoC Threat Feed Refresh | Refresh feeds immediately (also available as `f` on the main screen) |
| (4) Force Filesystem-Integrity Scan | Run a scan immediately (also available as `i` on the main screen) |
| (5) OTX AlienVault Threat Report | Build a date-ranged report of outbound threat-feed matches, each with a ready-made AlienVault OTX lookup link (see **The OTX AlienVault Threat Report**, below) |
| (6) Reset IOCMON back to Default Settings | Erase all customization and start fresh (see **Starting Over**, below) |
| (7) Import/Export IOCMON Settings | Save your configuration to a portable file, or load one from elsewhere (see **Importing/Exporting Settings**, below) |
| (8) Update IOCMON to Latest Version | Check for and install a newer Stable or Beta build |
| (9) Optional Entware Components | Install `screen`/`findutils`/`jq`, needed for a few optional features, and the required `timeout` (item 4) |
| (10) Advanced Settings | Every detection toggle and threshold — see the six submenus below |
| (11) Uninstall IOCMON | Fully remove IOCMON from the router |

### NetAPI Compromised Sites (no key needed, on by default)

Item (3) of **Select Feed Sources, Reputation, API Keys and Lookups** downloads NetAPI.com's two free lists of currently
compromised hosts on every feed refresh: about 140,000 domains (hacked or malicious sites) and about 34,000 IPv4
addresses and netblocks. It needs no account or key, so a fresh install has DNS watch coverage straight away,
now that URLhaus needs an abuse.ch key. The domains go to the DNS watch and the IPs to the connection watch, and
the IPs are also pushed to Skynet when that import is on. Both lists are merged and deduplicated with the other
feeds, so an indicator that several feeds list shows all of them (e.g. `feodo,netapi`). Alerts from this source
read `netapi` / `compromised-site` or `compromised-ip`. Many listed domains are legitimate sites that were
hacked, so a match means that site was serving something malicious recently, not that the whole site is
malicious. If one keeps alerting and you trust it, add it to the DNS exceptions list. IPv6 entries are skipped,
and the lists are not downloaded in the reduced JFFS-only mode.

### URLhaus and ThreatFox (abuse.ch Auth-Key required)

abuse.ch no longer offers keyless downloads of URLhaus or ThreatFox, so both are off until you give them a key.
Create a free account at auth.abuse.ch and copy your **Auth-Key** — one key works for both. Under
**Select Feed Sources, Reputation, API Keys and Lookups**, switch URLhaus (item 4) or ThreatFox (item 6) on, then enter the
key under its API Key item (5 or 7). When you switch the second one on, IOCMON offers to reuse the key you already
entered. Leaving the menu with a feed on but no key switches it back off. If you upgraded from a version that ran
these feeds without a key, IOCMON switched them off once at startup and wrote a WARNING to its log.

- **URLhaus** (malware download sites) uses abuse.ch's 30-day CSV export. IOCMON keeps each host that is still
  online or was added in the last 2 days: a domain goes to the DNS watch and, new now, a bare IP address goes
  to the connection watch (and to Skynet, if that import is on). Each alert names the threat type, how many
  malware URLs that host serves, and up to six URLhaus tags, e.g.
  `malware_download; 2 URL(s); tags: 32-bit elf mips Mozi`. URLhaus's latest 1,000 malware **payloads** are also
  added as MD5/SHA-256 hashes for the filesystem-integrity hash check, labelled with their malware family and
  file type, e.g. `Mozi (elf file)`.
- **ThreatFox** (botnet C2s, payload sites, malware hashes) uses its API's last 3 days of IOCs. Each alert
  names the malware family, the threat type, ThreatFox's confidence and its tags, e.g.
  `Cobalt Strike (botnet_cc; confidence: 75; tags: c2 CobaltStrike)`. A URL that points at a bare IP address now
  goes to the connection watch rather than the DNS watch. `jq` is optional: IOCMON reads the API data itself
  when it isn't installed.
- Alert emails for a URLhaus or ThreatFox match include a link to that host, IP or hash on the abuse.ch site.

### Optional: Q-Feeds (larger OSINT lists)

Under **Select Feed Sources, Reputation, API Keys and Lookups** you can turn on **Q-Feeds**, which adds a large list of malicious IPs
and domains (a few hundred thousand entries). It is off by default. Create a free Community account and API
token at tip.qfeeds.com, switch Q-Feeds on, then enter it under *Q-Feeds API Key*. The lists are downloaded
about once a day (adjustable under *Q-Feeds refresh*) and stored on your USB drive; they are not available in
the reduced JFFS-only mode. Alerts from this source read `qfeeds` / `osint-ip` or `osint-domain`.

### Optional: AbuseIPDB reputation check

Items (12)-(17) of **Select Feed Sources, Reputation, API Keys and Lookups** control an optional, informational-only
reputation lookup. When it is on, every conntrack feed match, DNS alert (feed match or tunneling heuristic) and
dropbear/httpd brute-force alert from a public IP is looked up in AbuseIPDB's `/api/v2/check` endpoint as the
alert is raised. Nothing about how the alert is handled changes - the result is only added as extra detail.

- **Getting started:** create a free account at abuseipdb.com, create an API key, switch item (12) on, then
  enter the key under item (13). The free plan allows 1,000 lookups per day. The key field stays grayed out
  while item (12) is off, and leaving the menu with no key entered switches item (12) back off.
- **What is shown:** abuse confidence score (0-100%), number of reports and distinct reporters, last reported
  date, the top three report categories (e.g. SSH, Brute-Force, Port Scan), country, usage type (data
  center, ISP, CDN...), ISP, domain, hostnames, and whether it is a Tor exit node or AbuseIPDB-whitelisted.
- **Where it appears:** the top of the dashboard (next to *Alerts Today*: the latest score, IP and country,
  plus lookups used today), the Reputation log (`u` hotkey, or `v` while it is showing), a compact tag at the
  end of the IoC Detections log line and the red alert banner, an INFO line in the activity log, and a full
  block in the alert email (with a link to the IP's AbuseIPDB page).
- **DNS alerts:** AbuseIPDB only accepts IP addresses. IOCMON takes the IP from dnsmasq's own `reply`/`cached`
  log lines for that domain (following CNAMEs) and never resolves a suspicious domain itself. With AdGuard Home
  as the DNS source, it uses the A/AAAA answers from AdGuard Home's query log instead; with Technitium, the answers in
  its query log; with Pi-hole, the reply lines of a Pi-hole log file (Pi-hole's API doesn't report answer IPs, so API
  mode can't check DNS alerts). If no public answer was
  logged (e.g. an ad-blocker answered `0.0.0.0`), the Reputation log records why it was skipped.
- **Privacy:** each flagged public IP is sent to AbuseIPDB. LAN, CGNAT, loopback and link-local addresses are
  never looked up.
- **Staying within the quota:** results are cached per IP for item (14) hours; item (15) sets how many days
  of reports each lookup covers; item (16) is a daily ceiling (keep it below your plan's limit) and item (17)
  caps lookups in a single scan cycle. If AbuseIPDB answers "rate limited" or rejects the key, lookups pause
  automatically and the dashboard says so.
- Requires the USB drive (not available in the reduced JFFS-only mode).
- **Testing it:** the `t` test alert runs a full, live AbuseIPDB lookup (one real check from your daily quota)
  on the feed IP it simulates, so you can confirm the whole path without waiting for a real hit. Every output
  is marked as a test - `[SIMULATED TEST]` in the Reputation log, `SIMULATED TEST -` in the activity log, a
  `TEST` prefix on the IoC-log tag and dashboard slot, and a test note in the email - while the score, reports,
  categories and other details are the real values AbuseIPDB returned. The result is also shown on the test
  screen itself. A test always does a fresh lookup (it never reuses a cached result) and isn't held back by the
  per-cycle limit, but it still respects the daily ceiling and any rate-limit pause.

### Research: looking up an IP or domain

Item **(L) Lookup Threat Indicator** under *Research* in **Select Feed Sources, Reputation, API Keys and Lookups**
asks for any IPv4 address or domain and searches every feed IOCMON has downloaded for it. A pasted URL, a port,
or a defanged entry such as `hxxp://evil[.]com/path` is reduced to its host. Feeds that are switched off, or have
not downloaded yet, are not searched, and IPv6 can't be looked up because the feeds are IPv4 only.

- **Feed matches:** every feed that lists it, with the detail that feed carries (family, threat type, confidence,
  tags). An IP inside a listed netblock is shown with that netblock, plus the Spamhaus SBL reference.
- **Related listings (domains):** listed parent domains (`a.b.evil.com` finds `evil.com`) and listed subdomains
  of what you typed (the first 20). DNS watch itself only alerts on the exact name.
- **URLhaus and ThreatFox records:** the full downloads, including URLhaus URLs that are offline or older than DNS
  watch uses: count, first and last added, threat, tags and the newest five URLs; and up to five ThreatFox entries
  with malware, aliases, confidence, first and last seen, reporter, reference and a link to the entry.
- **Local alert history:** how often IOCMON itself alerted on it (a domain includes its subdomains), with the
  newest five alerts.
- **Exception lists:** whether the IP/CIDR, DNS exception or shared-hosting list covers it, which explains why it
  may never alert or is logged as Info.
- **Lookup links:** AlienVault OTX, URLhaus, ThreatFox and (for an IP) AbuseIPDB.
- **AbuseIPDB:** when the reputation check is on, a y/n prompt offers one live lookup (one of the day's quota); a
  result still in the cache is shown without asking. A domain uses its last DNS answer from the query log, and
  IOCMON never resolves it itself. The lookup is written to the Reputation log marked `[MANUAL LOOKUP]` and does
  not replace the dashboard's latest-score slot.

### Advanced Settings, by what you're trying to achieve

**"I want to control email alerts"** → *Alerting & Notifications*
Turn alert emails on/off, and cap how many can send per hour (0 = unlimited) — useful if you're worried about
a noisy detection flooding your inbox. Choose whether the on-screen SECURITY ALERT banner appears at the top
of the dashboard (default) or just above the timer/hotkey line at the bottom.

**Alert severity and the alert level.** Every alert has a severity, shown as its colour in the dashboard's
"Recent IoC Detections" panel and on the web page:

| Severity | What gets it |
|---|---|
| **Critical** (red) | A connection to a feed-listed IP; a file matching a malware hash; `.ssh`, startup-script, `/etc`, `*.conf.add` or permission changes; new executables; new cron entries; new port-forward/UPnP rules; dropbear/httpd brute force; changes to watched NVRAM settings; a DNS match that is escalated (below); the (T) simulated test |
| **Warning** (yellow) | A DNS lookup of a feed-listed domain; a change to `wan_dns`, `wan0_dns` or `wan1_dns`, which the firmware rewrites itself on a WAN reconnect |
| **Info** (gray) | DNS-tunneling heuristic hits; a DNS feed match on a shared-hosting domain (see DNS Watch below), or one whose answer address AbuseIPDB marks as whitelisted |

*Alert level* (item 4) decides which alerts raise the SECURITY ALERT banner and send email. **All Alerts** does so
for every alert. **Critical Only**, the default for new installs, does so only for Critical ones; Warning and Info
alerts are still written to the IoC log, the activity log and the web page, just without the banner or email.
Upgrading from the older "Feed Matches Only" setting moves you to Critical Only, otherwise to All Alerts.

A DNS feed match becomes Critical when ThreatFox lists the domain as botnet C2, or when the AbuseIPDB check (if on)
scores the domain's IP at or above item 5 (default 75%). Malware hosts are often new and have few reports, so most
real DNS hits will stay Warning; the escalation only lifts the clearest cases. Item 5 never stops an alert from being
made; it only raises a Warning to Critical. Two things lower a DNS match to Info first, even when ThreatFox says botnet
C2: a domain on the shared-hosting list, or an answer address that AbuseIPDB marks as whitelisted (large providers such
as Google). Malware sometimes keeps its settings on sites like YouTube, so feeds can list those sites as C2 although
visiting them is harmless.

**"I want to watch DNS lookups against known-bad domains, or catch DNS tunneling"** → *DNS Watch & Tunneling
Detection*
IOCMON reads lookups from the router's own dnsmasq by default. It can read them from AdGuard Home, Pi-hole or
Technitium DNS Server instead, set by *DNS query source* (item 11); each has its own section below.
Turn on feed-based DNS matching (this also offers to enable the router's own dnsmasq query logging, which it
needs to see anything). Turning the DNS watch back off removes that query-logging line and restarts dnsmasq,
so the router stops logging every lookup. IOCMON finds where dnsmasq's queries are written automatically
(normal syslog, a `log-facility=` file, or a syslog-ng/scribe `dnsmasq.log`); if your setup routes them somewhere
it can't detect, set the file path yourself under *DNS query log file*. IOCMON remembers its place in that file by
byte position and reads only the lines added since the last cycle, so a large log (Diversion's can pass 100 MB a day)
costs no more to watch than a small one. When the log is rotated (`-1`, `1` or `.1`), the unread end of the old copy
is read first. On the first run, or if its place is lost, at most the last 4 MB are read. Add domains to the exceptions list for known false positives (e.g. a CDN flagged only
because a malicious URL was once hosted there). Separately, turn on the behavioral tunneling/exfiltration
heuristic if you want to catch unusually long or high-volume DNS query patterns — this is off by default since
it can false-positive against legitimate high-subdomain-churn services; the same exceptions list quiets it too.
Its hits are always Info.

DNS watch reads each log line once: the lines counted at the start of a check are read as one range, and lines
written during the check wait for the next one. When the syslog rotates, the unread lines at the end of
`syslog.log-1` are read before the new file. Domain matching ignores case.

*Shared-hosting domains* (item 3) is a second list, preloaded with sites such as github.com, amazonaws.com,
microsoft.com, google.com, youtube.com, roblox.com, steamcommunity.com, `in-addr.arpa` and `ip6.arpa`. Upgrading from
v2.0.10 or earlier adds google.com, youtube.com, googlevideo.com, ytimg.com, youtu.be and ggpht.com to an existing list
once. Feeds such as URLhaus list these
because malware really is downloaded from them, so a lookup of one is usually harmless. A match on one of these
domains, or any subdomain, is kept in the log as Info rather than dropped. Unlike the exceptions list, nothing is
hidden: in the Critical Only level it just never raises the banner or email. Edit the list like any other; entries
must be plain domain names.

**AdGuard Home.** When AdGuard Home runs on the router, it answers DNS on port 53 and dnsmasq never sees your
devices' lookups. With *DNS query source* (item 11) on `auto` (the default), IOCMON notices this and reads AdGuard
Home's own query log through its API instead; the other two choices force one source. Everything else (feeds,
exceptions, the tunneling heuristic, alerts, emails, AbuseIPDB) works the same.
- Enter the login you use for AdGuard Home's web page under *AdGuard Home API login* (item 12). The menu shows
  `<set> | <connected>` in green, or `<set> | <not connected>` in yellow; open item 12 to see the reason. The login
  is kept base64-encoded (with `openssl`) in `iocmon.cfg`, readable by root only, and is never placed on a command
  line. Base64 hides it from a casual glance but is not encryption: anyone who can read the file can decode it.
  Answer "no" to including API keys when exporting settings and the login is left out too.
- Without a login, IOCMON skips DNS watch and shows a yellow warning in each scan and on the dashboard, plus one
  warning in the log. Everything else keeps running, and DNS watch resumes on the next cycle after you add the login.
- Needs Entware `jq` (Configuration Menu → Optional Entware Components) and AdGuard Home's query log switched on
  (AdGuard Home: Settings → DNS settings → Query logs). If AdGuard Home anonymizes client IPs, alerts can't name
  the device.
- IOCMON finds AdGuard Home's address in `AdGuardHome.yaml`. If that doesn't work for your setup, enter your own
  address, e.g. `http://192.168.50.1:3000`, under *AdGuard Home API address* (item 13); `auto` goes back to the yaml.
- **Backup AdGuard Home (optional).** If you run a second AdGuard Home, for example behind a Keepalived virtual IP,
  enter its login under item 14 and its address under item 15; each has its own port and login, and the two can run
  different versions. With an AdGuard Home that isn't on the router, set *DNS query source* (item 11) to AdGuard Home.
  IOCMON tries the primary at the start of every check, and reads the backup only if the primary has no login, can't
  be reached, or its query log can't be read. It continues from the last query it checked, so a takeover loses
  nothing. While the backup is in use, the dashboard and web page show its address in yellow, and the log records the
  switch and the return. If both fail, both places say so.
- The backup is chosen by whether the primary's API answers, not by which server holds the virtual IP. If the virtual
  IP moves but the primary's API still answers, IOCMON keeps reading the primary and won't see lookups the backup
  answers. Queries the backup answered after IOCMON's last check, just before the primary returned, aren't read.
- Every check reads all queries since the previous one, including those made while IOCMON was stopped. The first
  check starts from "now" rather than alerting on old history. If more than 10,000 queries arrive between two
  checks, a WARNING in the log says older ones were skipped (raise `aghmaxpages` in `iocmon.cfg`).
- Queries AdGuard Home already blocked never left your network and are skipped. Switch on *Also check queries
  AdGuard Home already blocked* (item 16) to be alerted when a device keeps trying a known-bad domain anyway.

**Pi-hole.** Pi-hole v6 is supported, either on another machine or on the router itself (the Entware port of
Pi-hole). `auto` never picks Pi-hole: set *DNS query source* (item 11) to 4, Pi-hole. Pi-hole v5 uses a different
API and is not supported; IOCMON says so in the log and the menu if it finds one.
- **Read method (item 17):** *API* reads Pi-hole's query API (needs Entware `jq`). *Log file* reads its `pihole.log`,
  which is the same format as dnsmasq's log, so it also gives AbuseIPDB the IP each domain was answered with (the API
  doesn't report answer IPs).
- **API address (item 18):** e.g. `https://192.168.50.5` or `http://192.168.50.1:5080`. For a Pi-hole on the router,
  `auto` reads the web port from `/opt/etc/pihole/pihole.toml` (`webserver.port`). The Entware port suggests moving
  it off 80/443, e.g. to `5080,5443s`.
- **Password (item 19):** Pi-hole v6 has no username. Use an **app password**, created in Pi-hole's web interface
  under Settings → Web interface / API (Expert mode): it skips two-factor login and can be revoked on its own. Your
  web password also works, unless two-factor login is on. It is kept base64-encoded in `iocmon.cfg` like the AdGuard
  Home login, is sent to Pi-hole on stdin, and is left out of exports when you answer "no". IOCMON keeps one Pi-hole
  session in RAM and reuses it, so it doesn't use up Pi-hole's limited API sessions.
- **Log file (item 18 in log mode):** `auto` looks for `/opt/var/log/pihole/pihole.log`, then
  `/var/log/pihole/pihole.log`; a remote Pi-hole's log can be used if it is mounted on the router. The Entware port
  turns query logging off by default (`dns.queryLogging = false` in `pihole.toml`) to save wear on the drive; IOCMON
  does not change that, and tells you to use the API instead.
- **Backup Pi-hole (items 20-22):** devices usually send lookups to both Pi-holes, so the backup is read every cycle
  alongside the primary, each with its own method, address or log file, and password. If one can't be read, the other
  still is, and the dashboard and web page show it in yellow.
- **Blocked queries** are skipped unless *Also check queries Pi-hole already blocked* (item 23) is on.
- **When Pi-hole only sees the router:** if this router's dnsmasq forwards devices' lookups to Pi-hole, every query in
  Pi-hole comes from the router, so the device behind each lookup can't be identified. IOCMON logs one WARNING when
  that happens. Use `dnsmasq` as the source instead, or have DHCP hand devices the Pi-hole's own address.
- As with AdGuard Home, the first check starts from "now", and later checks read every query since the previous one.

**Technitium DNS Server.** Technitium, on another machine or in Docker, is read through its API. `auto` never picks it:
set *DNS query source* (item 11) to 5, Technitium.
- **What Technitium needs:** a query-log app, such as **Query Logs (Sqlite)** from its App Store (Apps → App Store).
  Without one, Technitium keeps no query log that can be read, and IOCMON says so in the log and the menu. IOCMON finds
  the installed app by itself. It also needs Entware `jq`.
- **API address (item 24):** the address of Technitium's web console, e.g. `http://192.168.50.5:5380` (HTTP), or
  `https://192.168.50.5:53443` if its HTTPS console is on.
- **API token (item 25):** in Technitium's web console, open the user menu at the top right and choose *Create API
  Token*. A token doesn't expire and isn't affected by two-factor login. A user with only **Logs: View** permission is
  enough (Administration → Users, then Permissions), so the token can't change anything. The token is kept
  base64-encoded in `iocmon.cfg`, is sent to Technitium on stdin, and is left out of exports when you answer "no".
- **Backup Technitium (items 26 and 27):** devices usually send lookups to both servers, so the backup is read every
  cycle alongside the primary, with its own address and token. If one can't be read, the other still is, and the
  dashboard and web page show it in yellow.
- **Blocked queries** (Blocked, UpstreamBlocked, CacheBlocked) are skipped unless *Also check queries Technitium
  already blocked* (item 28) is on.
- **AbuseIPDB:** Technitium's query log includes the answer, so DNS alerts get the answered IP checked, as with
  AdGuard Home.
- As with Pi-hole, IOCMON logs one WARNING when nearly every query comes from the router itself, and the first check
  starts from "now".

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
In hash mode, a change to a critical file with no recorded hash yet (the first change after switching to hash mode
or to a new drive) alerts, so a first real edit is never missed. The first new Entware cron entry and the first
port-forward or UPnP rule alert even when the router had none before. A scan that reads no NAT rules at all
(for example during a firewall restart) keeps the previous list, so the rules coming back don't alert.

**"I want to watch the router's own configuration for tampering"** → *Network & System Watches*
Watch live connections against known-malicious IPs, watch a curated list of security-relevant NVRAM settings
(SSH/Telnet exposure, WAN DNS), and alert on unexpected new port-forward/DMZ/UPnP rules. The NVRAM values are
compared every monitor cycle, and every change is written to the activity log as an INFO line with its old and new
value and when the old value was last recorded. Only the first change in 6 hours also raises an alert, so a value
that changes back still shows in the log. `wan0_dns` holds the DNS servers in use right now, which the firmware
rewrites on a WAN reconnect or DHCP renewal, so it can change without anyone editing a setting. If a specific IP or
CIDR range keeps matching a feed and you know it's safe, add it to the IP/CIDR Exceptions list (item 4) — unlike
the watched/excluded folder lists under Filesystem Integrity, this is single IPs or ranges (e.g. `204.44.63.22`
or `204.44.0.0/16`), not a hostname, and it's checked before the connection is ever compared to a feed. After the
address, IOCMON asks for an optional short note (up to 64 characters, Enter for none) describing the entry, shown
beside it in the list and in the Research lookup. Editing an entry offers to change its note too (`-` removes it). The same
list is honored by the Skynet import: an excepted address inside a banned feed range is cut out of that range, and
the rest of the range stays banned.

If Skynet refuses an import (for example while it is busy with its own maintenance), IOCMON tries again after 30
seconds and again after a further 60, so a feed refresh can take up to 90 seconds longer. Until an import succeeds,
the previous IOCMON bans stay in force. If all three attempts fail, the activity log gets a WARNING quoting Skynet's
last message, and Skynet's full output for each attempt (without its banner) is kept in
`<drive>/iocmon.d/state/skynet_import.log` for you to look at later.

An import normally takes one to three minutes; the progress line shows the seconds so far. If Skynet hasn't finished
after 15 minutes, IOCMON stops it (and anything it started), logs an ERROR, keeps the previous bans and carries on;
it tries again at the next feed refresh rather than at once. A rule removal gets 3 minutes. This keeps a stuck Skynet
from stopping IOCMON's own detection. If it happens, check Skynet with `sh /jffs/scripts/firewall debug info`.

**"I want to change how often it checks, how much it logs, or how it updates itself"** → *General / Script
Behavior*
Main loop interval, log size cap, where the activity log lives, whether to autostart on reboot, IOCMON's own
self-update schedule/track, and the router web interface tab.

Item (9) adds an **IOCMON** tab under the **Addons** menu of the router's web interface (firmware 386.1 or later). It
shows the alert state, feeds, watches, filesystem integrity, a 14-day activity chart and the last 14 days of each log,
with search, filters and lookup links. It updates after each monitor cycle, so the monitor must be running. If updates stop, the tab shows
MONITOR NOT RESPONDING, which can also mean the monitor is paused or open in a menu. The tab needs a web interface
login, and no API keys, passwords or settings are published to it. Turning it on edits `services-start` and
`service-event`, so expect one `startup-script-edit` alert for each at the next filesystem scan.

The tab's buttons update feeds, scan the filesystem, simulate a detection and check for updates, one at a time, and
show progress and the result below the bar. **Start Monitor** appears only when the monitor looks down and needs the
Entware `screen` package. **Acknowledge** in the alert banner works like `(A)`. Simulate Detection sends a real alert
email if email is on. Logs can't be cleared and settings can't be changed from the tab.

The tab checks for updates when opened, at most every 6 hours. If a newer version is on your current track,
**Install Update** installs it, the monitor restarts at its next cycle and the page reloads. It never installs an older
version. Whether started here, from the menu or by the nightly auto-update, a download that fails its check or can't
replace the current script is not installed, and the current version keeps running. **Full History** loads up to 20,000 rows of the selected log, kept on the router for 30 minutes.
**Download CSV** saves every row of the selected log that matches the search and kind, in the order shown, not just
the current page; use Full History first to include older rows. The file is UTF-8, with times as
`YYYY-MM-DD HH:MM:SS` in the router's local time. A cell that starts with `=`, `+`, `-` or `@` gets a leading `'`, so a
spreadsheet treats it as text: login names and domains in these logs can be chosen by an attacker.

**Clear Log.** Below the rows of every log page, above *Prev/Next*, a right-aligned button clears the log you are viewing
(*Clear IoC Detections Log*, *Clear Dropbear Log* and so on), after a confirmation. It does exactly what the `(R)` hotkey
does: the whole log on the router and its rotated copies are erased, for the page and the IOCMON screen alike.

**Exception switch.** IoC Detections rows that have an exception list show an *Exception* switch on the right. Turning it on
(after a confirmation) adds the item to its list; turning it off removes it. Rows already in the log stay; the exception
only stops future alerts.
- DNS rows add the base domain, as the `(Z)` hotkey does, so `abc.vod.pv-cdn.net` adds `pv-cdn.net` and its subdomains.
- Conntrack rows add the destination IP to the IP/CIDR exceptions. Filesystem rows add the file to the excluded files,
  which stops every filesystem check on it; for a startup script, `.ssh` or `.conf.add` file the confirmation warns in
  red that IOCMON will no longer watch it for tampering. Cron rows add the entry to the cron exceptions.
- Brute-force, NVRAM, NAT rule, `/etc` critical-file, Kairos/Astraea signature and simulated rows have no switch.
- The page never sends the item itself to the router, only a short code. IOCMON looks the code up in its own log and
  checks the item with the same rules as the menus, so text in a log can't be turned into a command.
- *Excepted only* in the kind filter shows the rows whose item is excepted.

**Exceptions panel.** Hidden by default to keep the page short: its heading shows how many entries the four lists hold, and
the **Show**/**Hide** button beside it opens or closes the panel (your browser remembers which). Inside are four tabs, like the Logs panel: DNS Domains, IP Addresses, Files and Cron Entries, each showing how many
entries it holds. One list shows at a time, including entries added in the menus, each with a switch to remove it. Adding an
exception is only possible from a log row or the menus. The IP Addresses tab shows each entry's note beside it; notes are
added or changed in the IP/CIDR Exceptions menu (Network & System Watches → item 4), not on the page.

**Threat View.** The **Threat View** button at the left of the button row swaps the dashboard for a live world map of your
router's traffic; **Back to Dashboard** returns. Arcs run from your router's location to the other end of each new connection
(outbound) or from the other end to your router (inbound), sampled every 5 seconds:
- **Red, thicker:** an address from an unacknowledged Critical alert. **Yellow:** a Warning alert. These addresses keep a
  steady arc until you press **Acknowledge** (in the view or on the dashboard). **Grey-blue:** all other traffic.
- **Dimmer and dashed:** blocked attempts, both those the router's own firewall turned away and those Skynet dropped and
  logged, if Skynet is installed. Without Skynet, the router's own firewall rule records the same attempts.
- Below the map: blocked and allowed inbound, outbound, DNS lookups, Skynet-blocked outbound, Skynet's total drops and
  flagged traffic, each as new connections per minute (hover over a counter for what it counts). **Allowed in** counts
  only connections started from the internet that the firewall let in (port forwards, UPnP, a VPN server or a router
  service). Replies to connections your own devices opened belong to those connections, so on a home network without
  port forwards it is usually 0-2 a minute. Every DNS lookup to an outside server (port 53, or 853 for DNS over
  TLS) is a new connection, so DNS has its own counter and Outbound counts everything else. A router running its own
  resolver (Unbound, for example) can make thousands of lookups a minute. Without Skynet, the **Blocked out** and
  **Skynet drops** counters read "Not installed" and the feed's key leaves out SKYNET. Everything else works the same.
- Filters: inbound, outbound, allowed, blocked, **DNS lookups** (off by default, so DNS arcs and rows are hidden unless the
  address is flagged) and flagged only.
- Three tabs. **Live Feed** lists each connection with its device, flagged first, then inbound. Its Result column reads
  **ALLOWED** (the connection went through), **FIREWALL** (an unsolicited inbound attempt the router's own firewall
  dropped) or **SKYNET** (dropped by Skynet's blocklist, in either direction). **Top Countries** covers
  the last 15 minutes. **Replay** plays the last 15 minutes back at 1x, 4x or 16x, and the slider follows the playback.
- Click a dot on the map or a row to see that country's addresses, with OTX, AbuseIPDB and URLhaus links. The dotted line
  is the day/night boundary, and the clock shows UTC.
- **Expand** fills the browser window with the map at full width and the counters, filters and alert bar along the
  bottom. The tabs move into a panel that slides over the left of the map: the **FEED** tab on the left edge opens it
  and **HIDE** closes it, and the browser remembers which you chose. **Fullscreen** then fills the screen, and **Shrink**
  or Esc returns.
- Your location is the centre of your WAN address's country. **change** (bottom left) sets an exact latitude and
  longitude, kept only in that browser.

The router only collects this data while the view is open. It adds one firewall rule and one ipset per WAN interface, which
it removes 2 minutes after the view closes, and reads only new syslog lines for Skynet's entries. Countries come from
IPLocate.io's free IP to Country database (IP address data powered by IPLocate.io, CC BY-SA 4.0), which IOCMON downloads
to the USB drive once a month (a 9 MB zip; not available in JFFS-only mode). It needs no account or key. Google's and
Cloudflare's addresses, which are served from many cities at once, show under the company's country (US). No free table is
perfect: a server hosted abroad by a company can still show under the company's country. The first table is built in the
next monitor cycle after the web interface is turned on, with "[Updating Country IP Location Lookup Database]" on screen;
after that the monthly update runs with the feed refresh, as its own "Country lookup" line. Until it is built, the feed works but no arcs are drawn. IPv4 only. The map is from Natural Earth.

The activity log (`iocmon.log`) is kept on JFFS (`/jffs/addons/iocmon.d/iocmon.log`) by default. Item (3) moves it to
the external drive instead (`/tmp/mnt/<drive>/iocmon.d/state/iocmon.log`) to spare the router's flash from constant
log writes. Pressing it again moves it back. Both directions ask for confirmation and carry the existing log over.
If the drive is ever missing, IOCMON logs to JFFS temporarily and merges those lines back once the drive returns.

Logs are rotated, not trimmed. Item (2) sets the number of rows at which a log rotates (default 2000, 0 = never): the
log moves to `<name>.1`, the previous `.1` moves to `.2`, the previous `.2` is deleted, and a new, empty log starts. So
up to three times that many rows are kept per log. Rotation never rewrites a log in place, so a tool that follows
it (for example a syslog-ng `file()` source forwarding `iocmon.log` to a syslog server) never receives the same lines
twice. The activity log is checked every 6 hours, after the feed update check; the IoC, Dropbear, Hash-Check and
Reputation logs and the filesystem lists are checked each time a line is added. The dashboard, `(V)`, `(L)`, the OTX
report and the web tab read the rotated copies too, and `(R)` clears a log together with its rotated copies. Moving the
activity log with item (3) moves its rotated copies with it.

### Reducing False Positives

If a legitimate service, file, or scheduled task keeps triggering alerts, IOCMON has a purpose-built exception
list for nearly every watch instead of forcing you to disable the whole feature:

- **DNS**: add the domain to the DNS exceptions list (DNS Watch & Tunneling Detection → item 2).
- **Filesystem — a whole folder**: add its name to the excluded-folder-names list (item 5). Matches the name
  anywhere it appears under a watched tree.
- **Filesystem — a file type**: add the extension to the excluded-extensions list (item 6), e.g. `.log`.
- **Filesystem — one specific file**: add its full path to the excluded-files list (item 7).
- **Connections — one IP or range**: add it to the IP/CIDR Exceptions list (Network & System Watches → item 4).
- **Cron**: use the cron exceptions picker (item 13) to select a specific job from a live numbered list rather
  than retyping it by hand — this survives a managing tool later re-writing that job's own schedule. `(b)` adds
  every current cron job at once (already-excepted ones are skipped), so you can then delete just the ones you
  want watched; `(c)` clears the whole list after a y/n confirmation.

### Working alongside Kairos and Astraea

IOCMON recognizes Kairos (network time hardening) and Astraea (certificate integrity) on its own. Nothing needs
to be switched on, and nothing changes on a router without them.

- **The router's own lookups.** Astraea checks the certificate of each site your devices visit, and Kairos looks
  up its time servers, so the router itself looks up those names too. Both add-ons record those lookups in
  `/tmp/astraea/selfq` and `/tmp/kairos/selfq`. When DNS watch sees a lookup from the router itself (127.0.0.1,
  ::1 or any of the router's own addresses) for a name listed there within about a minute, it treats it as the
  add-on's, not a device's: no feed-match or tunneling alert, one INFO line in the activity log (at most once per
  name every 6 hours), and a count on the DNS cycle line. A device that looked up the same name still alerts as
  usual, and a router lookup that isn't in those files still alerts too.
- **Only while Kairos is running.** Kairos's file is used only while its status file `/tmp/kairos/status` was
  written in the last 3 minutes. An older Kairos without that file is checked through `nvram get kairos_time`
  instead. If neither shows Kairos running, its lookups are not set aside and alert like any other router lookup.
- **Astraea's verdict on alerts.** When Astraea is installed, a DNS or connection alert also asks it what it
  knows about the domain or address (`astraea intel`): **clear**, **confirm**, **unknown** or **contained**,
  with its reason. The verdict appears on the alert's log line, the web page (and its CSV) and the email. It is
  information only and never changes an alert's severity, the banner or whether an email is sent. Astraea often
  hasn't checked a site yet when the alert fires, so **unknown** is common.
- **Shared query logging.** Astraea adds its own `log-queries` line to `dnsmasq.conf.add` under a marker line.
  Turning IOCMON's DNS watch off, resetting or uninstalling IOCMON removes only IOCMON's own line.
- A connection the router makes for Astraea's certificate check to an address on an IP feed still raises a
  connection alert.

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

### Starting Over

If your configuration has drifted somewhere you don't want, use **Configuration Menu → (6) Reset IOCMON back
to Default Settings**. After a confirmation prompt explaining exactly what will happen, this erases the saved
config and restarts IOCMON fresh — every toggle, threshold, and list reverts to its shipped default, and you'll
be walked back through the initial drive-selection setup. This cannot be undone.

### Uninstalling

**Configuration Menu → (11) Uninstall IOCMON** removes the script, its cron jobs, its autostart hook, the
background SCREEN session, and the shell alias. After a second, separate confirmation, it also removes the
feed/state data from your USB drive. This is irreversible.

### Importing/Exporting Settings

**Configuration Menu → (7) Import/Export IOCMON Settings** lets you carry your configuration — every toggle,
threshold, and exclusion list — between routers, or keep a backup before experimenting:

- **Export** writes your current settings to a plain `.ioc` file, defaulting to `<your-router's-hostname>-
  config-export.ioc` on your feed storage drive (you can type a different path/filename instead). It asks
  separately whether to include your URLhaus/ThreatFox/Q-Feeds/AbuseIPDB API keys, AdGuard Home logins, Pi-hole
  passwords and Technitium API tokens — leave them out if you plan to share or store the file somewhere less trusted,
  and just re-enter them afterward (the API keys under Select Feed Sources, Reputation, API Keys and Lookups; the DNS
  logins under Advanced Settings → DNS Watch). Every other setting, including all the AbuseIPDB reputation-check
  settings, is always exported.
- On **import**, a key, login, password or token the file doesn't carry never wipes out this router's own — the
  existing one is kept.
  If URLhaus, ThreatFox, Q-Feeds or the AbuseIPDB check is switched on in the file but no key exists on either
  side, that feature is imported as switched off.
- **Import** loads a `.ioc` file and overwrites your current configuration with it, then restarts IOCMON. Your
  feed storage drive selection is always kept as this router's own — it's never overwritten by the import file.
  Any watched-folder path tied to the *old* router's drive label is automatically updated to this router's own
  label, and a manually-set DNS query log path is reset to auto-detect, since both are specific to the router
  that originally saved them.
- You can also import a `.ioc` file during first-time setup, right after selecting your feed storage drive — if
  you have one, this replaces the rest of the setup wizard with your imported settings instead.

### Support and Discussion Forum

Full support of this script is available on SNB Forums: 
https://www.snbforums.com/threads/97925/
