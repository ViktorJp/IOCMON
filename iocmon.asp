<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<!-- IOCMON-WebUI v1.4.1 -->
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="X-UA-Compatible" content="IE=Edge"/>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
<meta http-equiv="Pragma" content="no-cache"/>
<meta http-equiv="Expires" content="-1"/>
<link rel="shortcut icon" href="images/favicon.png"/>
<link rel="icon" href="images/favicon.png"/>
<title>IOCMON</title>
<link rel="stylesheet" type="text/css" href="index_style.css"/>
<link rel="stylesheet" type="text/css" href="form_style.css"/>
<script language="JavaScript" type="text/javascript" src="/js/jquery.js"></script>
<script language="JavaScript" type="text/javascript" src="/js/httpApi.js"></script>
<script language="JavaScript" type="text/javascript" src="/state.js"></script>
<script language="JavaScript" type="text/javascript" src="/general.js"></script>
<script language="JavaScript" type="text/javascript" src="/popup.js"></script>
<script language="JavaScript" type="text/javascript" src="/help.js"></script>
<script language="JavaScript" type="text/javascript" src="/validator.js"></script>
<style>
#ioc { --bg: #15181c; --panel: #20252b; --panel2: #2a3037; --button: #414a54; --buttonhover: #505b67; --line: #3b434c; --text: #d7dce1; --dim: #8b96a1;
       --cyan: #2fd0e4; --green: #4be38a; --amber: #ffc14d; --red: #ff5f52;
       background: var(--bg); color: var(--text); padding: 12px; font-family: "Segoe UI", Tahoma, Arial, sans-serif;
       font-size: 12px; line-height: 1.4; text-align: left; }
#ioc * { box-sizing: border-box; }
#ioc .mono, #ioc .num { font-family: Consolas, Menlo, "DejaVu Sans Mono", monospace; }
#ioc h2 { color: var(--cyan) !important; font-size: 11px !important; font-weight: 600; letter-spacing: 2px; margin: 0 0 8px 0;
          text-transform: uppercase; border: 0 !important; padding: 0; background: none !important; }
#ioc .panel { background: var(--panel); border-top: 1px solid var(--line); padding: 10px 12px; margin-top: 10px;
              clip-path: polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px)); }
#ioc .hdr { position: relative; overflow: hidden; display: flex; align-items: center; gap: 14px; padding: 14px 16px;
            background: linear-gradient(100deg, var(--panel2), var(--panel)); border-left: 4px solid var(--c, var(--cyan));
            clip-path: polygon(0 0, calc(100% - 20px) 0, 100% 20px, 100% 100%, 20px 100%, 0 calc(100% - 20px)); }
#ioc .hdr::after { content: ""; position: absolute; left: 0; right: 0; bottom: 0; height: 1px;
                   background: linear-gradient(90deg, var(--c, var(--cyan)), transparent); }
#ioc .dot { width: 14px; height: 14px; flex: none; background: var(--c, var(--cyan));
            clip-path: polygon(50% 0, 100% 50%, 50% 100%, 0 50%); }
#ioc .hdr.alert .dot { animation: iocpulse 1.2s ease-in-out infinite; }
@keyframes iocpulse { 50% { opacity: .25; } }
@media (prefers-reduced-motion: reduce) { #ioc .hdr.alert .dot { animation: none; } }
#ioc .hdr .state { font-size: 21px; font-weight: 600; letter-spacing: 1px; color: var(--c, var(--cyan)); }
#ioc .hdr .sub { color: var(--dim); }
#ioc .hdr .right { margin-left: auto; text-align: right; color: var(--dim); white-space: nowrap; }
#ioc .hdr .right b { color: var(--text); font-weight: 600; }
#ioc .banner { margin-top: 10px; padding: 8px 12px; overflow-wrap: anywhere; }
#ioc #b_alert, #ioc #b_update { align-items: center; gap: 12px; }
#ioc #b_alert_t, #ioc #b_update_t { flex: 1; min-width: 0; }
#ioc .actions { display: flex; gap: 6px; margin-top: 10px; flex-wrap: wrap; }
#ioc .btn { flex: 1; text-align: center; white-space: nowrap; padding: 7px 10px; background: var(--button); border-bottom: 2px solid var(--cyan); color: var(--text) !important;
            cursor: pointer; text-decoration: none; font-size: 11px; letter-spacing: 1px; text-transform: uppercase; }
#ioc .btn:hover { background: var(--buttonhover); }
#ioc .btn.dis, #ioc .btn.dis:hover { background: var(--panel2); color: var(--dim) !important; border-bottom-color: var(--line); cursor: default; }
#ioc .btn.ack { flex: none; background: transparent; border: 1px solid currentColor; color: inherit !important; }
#ioc .job { position: relative; overflow: hidden; margin-top: 6px; padding: 5px 10px; background: var(--panel); color: var(--dim); overflow-wrap: anywhere; display: none; }
#ioc .job.running { color: var(--cyan); }
#ioc .job.done { color: var(--green); }
#ioc .job.failed { color: var(--red); }
#ioc .job.running::after { content: ""; position: absolute; left: 0; bottom: 0; height: 2px; width: 30%; background: var(--cyan); animation: iocsweep 1.6s linear infinite; }
@keyframes iocsweep { from { transform: translateX(-100%); } to { transform: translateX(340%); } }
#ioc .banner.red { background: #4a1d1b; border-left: 4px solid var(--red); color: #ffd9d5; }
#ioc .banner.amber { background: #453517; border-left: 4px solid var(--amber); color: #ffe7b8; }
#ioc .tiles { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-top: 10px; }
#ioc .tile { background: var(--panel); padding: 9px 11px; min-width: 0; clip-path: polygon(0 0, calc(100% - 10px) 0, 100% 10px, 100% 100%, 0 100%); }
#ioc .tile .k { color: var(--dim); font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase; }
#ioc .tile .v { font-size: 30px; line-height: 1.2; color: var(--text); overflow-wrap: anywhere; }
#ioc .tile .v.small { font-size: 12px; padding-top: 5px; }
#ioc .tile .s { color: var(--dim); font-size: 11px; overflow-wrap: anywhere; }
#ioc .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 4px 18px; }
#ioc .row { display: flex; justify-content: space-between; gap: 12px; padding: 3px 0; border-bottom: 1px solid #2c333a; min-width: 0; }
#ioc .row .k { color: var(--dim); flex: none; }
#ioc .row .v { text-align: right; overflow-wrap: anywhere; min-width: 0; }
#ioc #w_dnslog { font-size: 11px; }
#ioc .on { color: var(--green) !important; }
#ioc .off { color: var(--dim) !important; }
#ioc .warn { color: var(--amber) !important; }
#ioc .bad { color: var(--red) !important; }
#ioc .plain { padding: 2px 0; overflow-wrap: anywhere; }
#ioc details { margin: 0 0 6px 12px; }
#ioc h2.split { display: flex; justify-content: space-between; align-items: baseline; }
#ioc .fcols { white-space: nowrap; flex: none; font-size: 12px; font-weight: 400; letter-spacing: 0; text-transform: none; }
#ioc h2 .fcols { color: var(--dim); }
#ioc .fcols .fi { display: inline-block; width: 10ch; text-align: right; }
#ioc .fcols .fu { display: inline-block; width: 12ch; text-align: left; }
#ioc summary { cursor: pointer; color: var(--cyan); padding: 2px 0; }
#ioc .list { max-height: 220px; overflow: auto; background: var(--bg); padding: 6px 8px; margin-top: 4px; font-size: 11px; }
#ioc .list div { overflow-wrap: anywhere; padding: 1px 0; }
#ioc .tabs { display: flex; gap: 2px; margin-bottom: 8px; }
#ioc .tabs a { flex: 1; text-align: center; padding: 6px 4px; background: var(--button); color: var(--text) !important; cursor: pointer;
               text-decoration: none; letter-spacing: 1px; font-size: 11px; text-transform: uppercase; }
#ioc .tabs a:hover { background: var(--buttonhover); }
#ioc .tabs a.sel { background: var(--cyan); color: #0f1518 !important; font-weight: 600; }
#ioc .tools { display: flex; gap: 6px; margin-bottom: 8px; align-items: center; }
#ioc .tools input, #ioc .tools select { background: var(--bg) !important; color: var(--text) !important; border: 1px solid var(--line) !important;
               padding: 3px 6px; height: 25px; font-size: 12px; }
#ioc .tools input { flex: 1; min-width: 0; }
#ioc .tools .btn { flex: none; padding: 4px 8px; font-size: 10px; }
#ioc .chartbox { position: relative; }
#ioc .chartbox svg { display: block; width: 100%; height: auto; }
#ioc .chartbox text { fill: var(--dim); font-size: 10px; }
#ioc .chartbox text.peak { fill: var(--text); }
#ioc .chartbox .hit { fill: transparent; }
#ioc .chartbox .hit:hover { fill: rgba(255, 255, 255, .05); }
#ioc .legend { display: flex; flex-wrap: wrap; gap: 4px 14px; margin-bottom: 6px; color: var(--dim); font-size: 11px; }
#ioc .legend i { display: inline-block; width: 9px; height: 9px; margin-right: 5px; }
#ioc .tip { position: absolute; top: 4px; display: none; background: var(--bg); border: 1px solid var(--line); padding: 5px 8px; font-size: 11px; white-space: nowrap; pointer-events: none; }
#ioc .tip b { display: block; font-weight: 600; }
#ioc .tip i { display: inline-block; width: 9px; height: 9px; margin-right: 5px; }
#ioc .entry { padding: 6px 0; border-bottom: 1px solid #2c333a; }
#ioc .entry .top { display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; }
#ioc .entry .when { color: var(--dim); font-size: 11px; white-space: nowrap; }
#ioc .entry .tag { background: var(--panel2); color: var(--cyan); font-size: 10px; letter-spacing: 1px; padding: 0 5px; text-transform: uppercase; }
#ioc .entry .main { overflow-wrap: anywhere; }
#ioc .entry.critical { border-left: 3px solid var(--red); padding-left: 8px; }
#ioc .entry.critical .main { color: var(--red); }
#ioc .entry.warning { border-left: 3px solid var(--amber); padding-left: 8px; }
#ioc .entry.warning .main { color: var(--amber); }
#ioc .entry.info { border-left: 3px solid var(--line); padding-left: 8px; }
#ioc .entry.info .main { color: var(--dim); }
#ioc .entry .sub { color: var(--dim); font-size: 11px; overflow-wrap: anywhere; }
#ioc .links a { color: var(--cyan) !important; margin-right: 10px; font-size: 11px; }
#ioc .pager { display: flex; justify-content: space-between; align-items: center; padding-top: 8px; color: var(--dim); }
#ioc .pager a { color: var(--cyan) !important; cursor: pointer; text-decoration: none; padding: 2px 6px; }
#ioc .pager a.dis { color: var(--line) !important; cursor: default; }
#ioc .foot { color: var(--dim); font-size: 10px; text-align: right; margin-top: 8px; }
@media (max-width: 700px) { #ioc .tiles { grid-template-columns: 1fr 1fr; } #ioc .grid { grid-template-columns: 1fr; } }
</style>
<script type="text/javascript">
var pagever = "1.4.1", datapath = "/ext/iocmon/", lastts = "", lastchange = 0, routerage = null, lastlogkey = "";
var logs = { ioc: [], dropbear: [], hash: [], reputation: [] }, curlog = "ioc", curpage = 0, pagesize = 25;
var job = { id: "", state: "" }, waiting = null, jobchain = false, jobstale = false, updateinfo = null, acktimer = null, updatelatest = "";
var full = {}, pendingfull = null, routerdate = "", recentdays = 14, recentrows = 2000, fullrows = 20000;
var jobnames = { feeds: "Feed update", scan: "Filesystem scan", simulate: "Simulated detection", check: "Update check", start: "Start monitor", update: "Update", full: "Full history" };
var chartkinds = [["conntrack", "Conntrack", "#3987e5"], ["dns", "DNS", "#d95926"], ["auth", "Auth", "#199e70"], ["fsintegrity", "Filesystem", "#c98500"], ["simulated", "Test", "#d55181"], ["other", "Cron, NVRAM, firewall", "#8b96a1"]];
var monthnames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
var sourcenames = [["tf", "ThreatFox"], ["sh", "Spamhaus DROP/EDROP"], ["fd", "Feodo Tracker"], ["na", "NetAPI Compromised Sites"], ["uh", "URLhaus"], ["qf", "Q-Feeds"]];

function byid(id) { return document.getElementById(id); }
function put(id, text, cls) { var e = byid(id); e.textContent = text; e.className = cls === undefined ? e.className : cls; }
function make(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; }
function clearnode(e) { while (e.firstChild) e.removeChild(e.firstChild); }
function unesc(s) { return s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&"); }

function fetchdata(file, done) {
  var x = new XMLHttpRequest();
  x.open("GET", datapath + file + "?_=" + Date.now(), true);
  x.onreadystatechange = function () {
    if (x.readyState !== 4) return;
    var ok = x.status === 200 && x.responseText.substring(0, 8) === "iocmon=1";
    done(ok ? x.responseText : null, x.status, x.getResponseHeader("Date"));
  };
  x.send(null);
}
function datalines(text) {
  var a = text.split("\n"), out = [], i;
  for (i = 1; i < a.length; i++) if (a[i] !== "") out.push(unesc(a[i]));
  return out;
}
function parsestatus(text) {
  var a = text.split("\n"), o = {}, i, p;
  for (i = 1; i < a.length; i++) { p = a[i].indexOf("="); if (p > 0) o[a[i].substring(0, p)] = unesc(a[i].substring(p + 1)); }
  return o;
}
function setstate(state, sub, color, alert) {
  var h = byid("hdr");
  h.className = alert ? "hdr alert" : "hdr";
  h.style.setProperty("--c", "var(--" + color + ")");
  put("h_state", state);
  put("h_sub", sub);
}
function onoff(on, text) { return on ? { t: text, c: "v on" } : { t: "off", c: "v off" }; }
function setrow(id, o) { put(id, o.t, o.c); }
function plural(n, w) { return n + " " + w + (n === "1" ? "" : "s"); }

function showstatus(d) {
  var pending = parseInt(d.pendingcount, 10) || 0, simonly = pending === 1 && / \| simulated \| /.test(d.pendingsummary || "");
  var limit = Math.max(3 * (parseInt(d.loop, 10) || 60), 300) * 1000, quiet = Date.now() - lastchange;
  if (routerage !== null) quiet = Math.max(quiet, routerage * 1000);
  setmonitor(quiet > limit);
  if (quiet > limit) setstate("MONITOR NOT RESPONDING", "No update for " + Math.floor(quiet / 60000) + " min. It may be stopped, paused, or open in a menu. Figures below are from " + d.time + ".", "amber", false);
  else if (pending > 0 && !simonly) setstate(pending + " ALERT" + (pending === 1 ? "" : "S"), "Unacknowledged IoC detections. Acknowledge here or with (A) on the IOCMON screen.", "red", true);
  else if (simonly) setstate("TEST ALERT", "One simulated detection is unacknowledged.", "amber", false);
  else setstate("NO ACTIVE ALERTS", "Monitor running. Last update " + d.time + ".", "cyan", false);

  put("h_ver", "v" + d.version + (d.track === "1" ? " beta" : ""));
  put("h_router", d.model + " (" + d.hostname + ")");
  put("h_uptime", d.uptime ? "Up " + d.uptime : "");

  byid("b_alert").style.display = pending > 0 ? "flex" : "none";
  byid("b_alert").className = simonly ? "banner amber" : "banner red";
  put("b_alert_t", "Latest: " + (d.pendingsummary || "see the IoC log"));
  updatelatest = d.updatever || (updateinfo && updateinfo.available === "1" && updateinfo.latest !== d.version ? updateinfo.latest : "");
  byid("b_update").style.display = updatelatest ? "flex" : "none";
  put("b_update_t", "Update available: v" + d.version + " to v" + updatelatest + ".");
  checkpage(d);

  put("t_feeds", Number(d.feedstotal || 0).toLocaleString());
  put("t_feedsub", "every " + d.feedhrs + "h, oldest " + d.feedsoldest);
  put("t_today", d.todaycount || "0");
  put("t_level", d.alertlevel === "critical" ? "Banner and email: Critical only" : d.alertlevel === "all" ? "Banner and email: all alerts" : "");
  put("t_last", d.lastalert || "none yet");
  put("t_rep", d.reputation || "AbuseIPDB off");

  var failover = d.dnsstate === "adguardhome" ? d.dnsfailover : "0";
  setrow("w_conn", onoff(d.conntrackon === "1", plural(d.conntrackchecked || "0", "dst ip") + ", checked " + (d.conntracklast || "n/a")));
  if (d.dnsstate === "off") setrow("w_dns", { t: "off", c: "v off" });
  else if (d.dnsstate === "waiting") setrow("w_dns", { t: "awaiting query-log setup", c: "v warn" });
  else if (d.dnsstate === "nologin") setrow("w_dns", { t: "skipped, AdGuard Home login missing", c: "v warn" });
  else if (failover === "2") setrow("w_dns", { t: "AdGuard Home not answering, last checked " + (d.dnslast || "n/a"), c: "v warn" });
  else setrow("w_dns", { t: (failover === "1" ? "AdGuard Home backup, " : d.dnsstate === "adguardhome" ? "AdGuard Home, " : "") + (d.dnschecked || "0") + " checked at " + (d.dnslast || "n/a"), c: failover === "1" ? "v warn" : "v on" });
  put("w_dnslog", d.dnslog || "-", d.dnsstate === "nologin" || failover === "1" || failover === "2" ? "v warn" : d.dnslog && d.dnsstate !== "off" ? "v on" : "v off");
  setrow("w_auth", onoff(d.authon === "1", "+" + (d.authchecked || "0") + " new, checked " + (d.authlast || "n/a")));
  setrow("w_nvram", onoff(d.nvramon === "1", d.nvramvars + " vars, checked " + (d.nvramlast || "n/a")));
  if (d.fson !== "1") setrow("w_fs", { t: "off", c: "v off" });
  else if (d.fsbaseline === "0") setrow("w_fs", { t: "no baseline yet", c: "v warn" });
  else setrow("w_fs", { t: d.fsbaseline + " files baselined", c: "v on" });

  showfeeds(d);
  setrow("s_email", d.email === "1" ? { t: "on, limit " + (d.ratelimit === "0" ? "unlimited" : d.ratelimit + "/h"), c: "v on" } : { t: "off", c: "v off" });
  setrow("s_cron", d.cron === "1" ? { t: "scheduled", c: "v on" } : { t: "not scheduled", c: "v off" });
  put("s_storage", d.storage || "-");
  put("s_free", d.drivefree || "n/a");
  put("s_time", d.time);
  routerdate = d.time || "";
  put("s_loop", d.loop + "s");

  byid("fs_err").style.display = d.fserrcount && d.fserrcount !== "0" ? "block" : "none";
  put("fs_err", d.fserrcount + " scan error(s) - first: " + d.fserrfirst);
}

function checkpage(d) {
  var mismatch = d.webui && d.webui !== pagever, tried = "";
  byid("b_page").style.display = mismatch ? "block" : "none";
  if (!mismatch) return;
  put("b_page", "This page is v" + pagever + " but IOCMON expects v" + d.webui + ". The newer page could not be loaded: see the IOCMON activity log.");
  try { tried = sessionStorage.getItem("iocmonpage") || ""; } catch (e) { return; }
  if (tried === d.webui) return;
  try { sessionStorage.setItem("iocmonpage", d.webui); } catch (e) { return; }
  window.location.reload();
}

function feedrow(label, items, when) {
  var row = make("div", "row"), cols = make("span", "v num fcols");
  row.appendChild(make("span", "k", label));
  cols.appendChild(make("span", "fi", items));
  cols.appendChild(document.createTextNode(" | "));
  cols.appendChild(make("span", "fu", when || "-"));
  row.appendChild(cols);
  return row;
}

function showfeeds(d) {
  var box = byid("f_rows"), have = {}, parts = (d.feedsources || "").split(" "), i, p, name;
  clearnode(box);
  for (i = 0; i < parts.length; i++) { p = parts[i].indexOf("="); if (p > 0) have[parts[i].substring(0, p)] = parts[i].substring(p + 1); }
  for (i = 0; i < sourcenames.length; i++) {
    name = sourcenames[i][0];
    if (have[name] === undefined) continue;
    box.appendChild(feedrow(sourcenames[i][1], have[name], d["fetched_" + name]));
    delete have[name];
  }
  for (name in have) box.appendChild(feedrow(name, have[name], ""));
  if (!box.firstChild) box.appendChild(make("div", "plain off", "No feeds loaded yet."));
}

function postaction(name) {
  var f = document.form, q = [], i, x;
  f.action_mode.value = "apply"; f.action_wait.value = "0"; f.action_script.value = "start_" + name;
  for (i = 0; i < f.elements.length; i++) if (f.elements[i].name) q.push(encodeURIComponent(f.elements[i].name) + "=" + encodeURIComponent(f.elements[i].value));
  x = new XMLHttpRequest();
  x.open("POST", "/start_apply.htm", true);
  x.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
  x.send(q.join("&"));
}
function setmonitor(down) { byid("a_iocmonstart").style.display = down ? "" : "none"; }
function busy() { return !!waiting || (job.state === "running" && !jobstale); }
function drawjob(note) {
  var i, a = byid("actions").getElementsByTagName("a"), label = jobnames[job.action] || "Job";
  for (i = 0; i < a.length; i++) a[i].className = busy() ? "btn dis" : "btn";
  if (note) { put("jobline", note, "job failed"); }
  else if (waiting) put("jobline", "Sent. Waiting for the router...", "job running");
  else if (!job.id) put("jobline", "", "job");
  else if (jobstale) put("jobline", label + " has not finished after 30 minutes. It has probably failed: see the IOCMON activity log.", "job failed");
  else if (job.state === "running") put("jobline", label + " running...", "job running");
  else put("jobline", label + (job.state === "done" ? " finished " : " failed ") + job.time + (job.msg ? ": " + job.msg : ""), job.state === "done" ? "job done" : "job failed");
  byid("jobline").style.display = byid("jobline").textContent ? "block" : "none";
}
function polljob() {
  fetchdata("job.htm", function (text, code, hdate) {
    var d = text ? parsestatus(text) : null, was = !!waiting || job.state === "running", note = "", rt = hdate ? Date.parse(hdate) : NaN;
    if (d) {
      job = d;
      if (waiting && d.id !== waiting.prev) waiting = null;
      jobstale = d.state === "running" && !isNaN(rt) && Math.floor(rt / 1000) - parseInt(d.started, 10) > 1800;
    }
    if (waiting && Date.now() - waiting.at > 30000) {
      waiting = null;
      note = "No response from the router. Log in again, or toggle the web interface off and on in IOCMON.";
    }
    drawjob(note);
    if (was && !busy()) { finishfull(); loadupdate(); loadlogs(); loadfs(); poll(); }
    if (busy() && !jobchain) { jobchain = true; setTimeout(function () { jobchain = false; polljob(); }, 2000); }
  });
}
function runaction(name) {
  if (busy()) return;
  if (name === "iocmonsimulate" && !confirm("Raise a simulated detection? It shows as a test alert here and sends a real alert email if email is on.")) return;
  waiting = { prev: job.id, at: Date.now() };
  drawjob();
  postaction(name);
  polljob();
}
function installupdate() {
  if (busy() || !updatelatest) return;
  if (confirm("Install IOCMON v" + updatelatest + " from your current update track? A running monitor restarts into it at its next cycle.")) runaction("iocmonupdate");
}
function togglefull() {
  if (full[curlog]) { full[curlog] = false; loadlog(curlog); drawfull(); return; }
  if (busy()) return;
  pendingfull = { log: curlog, prev: job.id };
  runaction("iocmonfull" + curlog);
}
function finishfull() {
  var p = pendingfull;
  pendingfull = null;
  if (!p || job.id === p.prev || job.action !== "full" || job.state !== "done") return;
  full[p.log] = true;
  fetchdata("full-" + p.log + ".htm", function (text) {
    if (!text) { full[p.log] = false; loadlog(p.log); drawfull(); return; }
    storelog(p.log, text);
    drawfull();
  });
}
function drawfull() { put("l_full", full[curlog] ? "Recent Only" : "Full History"); }
function acknowledge() {
  put("a_ack", "Acknowledging...");
  postaction("iocmonack");
  clearTimeout(acktimer);
  setTimeout(poll, 2000);
  acktimer = setTimeout(function () { poll(); put("a_ack", "Acknowledge"); }, 6000);
}
function loadupdate() { fetchdata("update.htm", function (text) { updateinfo = text ? parsestatus(text) : null; }); }

function poll() {
  polljob();
  loadupdate();
  fetchdata("status.htm", function (text, code, hdate) {
    if (!text) {
      if (code === 200) setstate("SESSION EXPIRED", "Log in to the router again and reload this page.", "amber", false);
      else { setstate("NO DATA YET", "The monitor hasn't published data. It appears after its next cycle, if it is running.", "amber", false); setmonitor(true); }
      return;
    }
    var d = parsestatus(text), rt = hdate ? Date.parse(hdate) : NaN;
    if (d.ts !== lastts) { lastts = d.ts; lastchange = Date.now(); }
    routerage = isNaN(rt) ? null : Math.max(0, Math.floor(rt / 1000) - parseInt(d.ts, 10));
    showstatus(d);
    if (d.ts !== lastlogkey) { lastlogkey = d.ts; loadlogs(); loadfs(); }
  });
}

function parts(line) { return line.split(" | "); }
function trim(s) { return s.replace(/^\s+|\s+$/g, ""); }
function parseioc(line) {
  var p = parts(line), rep = "", intel = "", sev = "", n;
  if (/^sev:(critical|warning|info)$/.test(p[p.length - 1])) sev = p.pop().slice(4);
  if (p.length < 5) return { raw: line };
  n = p.length;
  if (/^Astraea (clear|confirm|unknown|contained): /.test(p[n - 1])) { intel = p[n - 1]; n--; }
  if (/^(TEST )?AbuseIPDB /.test(p[n - 1])) { rep = p[n - 1]; n--; }
  if (n < 5) return { raw: line };
  return { when: p[0], tag: p[1], main: p.slice(2, n - 2).join(" | "), sub: p[n - 2] + " - " + p[n - 1], rep: rep, intel: intel, indicator: p.slice(2, n - 2).join(" | "), source: p[n - 2], detail: p[n - 1], sev: sev };
}
function parserep(line) {
  var p = parts(line), m;
  if (p.length < 3) return { raw: line };
  m = /^(\d+)%$/.exec(trim(p[2]));
  if (m) return { when: p[0], tag: "score " + m[1] + "%", main: p[1], sub: p.slice(3).join(" | "), score: parseInt(m[1], 10), indicator: trim(p[1]) };
  return { when: p[0], tag: "not checked", main: p[1], sub: p.slice(2).join(" | "), indicator: trim(p[1]) };
}
function parsedrop(line) {
  var m = /^([A-Z][a-z]{2} \d{2} \d{4} \d{2}:\d{2}:\d{2}) (.*)$/.exec(line), ip;
  if (!m) return { raw: line };
  ip = /(\d{1,3}(?:\.\d{1,3}){3})/.exec(m[2]);
  return { when: m[1], tag: "dropbear", main: m[2], indicator: ip ? ip[1] : "" };
}
function parsehash(line) {
  var p = parts(line);
  if (p.length < 4) return { raw: line };
  return { when: p[0], tag: /^MATCH/.test(p[p.length - 1]) ? "match" : "no match", main: p[1], sub: p.slice(2).join(" | "), bad: /^MATCH/.test(p[p.length - 1]) };
}
var parsers = { ioc: parseioc, dropbear: parsedrop, hash: parsehash, reputation: parserep };

function storelog(name, text) {
  var a = text ? datalines(text) : [], out = [], i, r;
  for (i = a.length - 1; i >= 0; i--) { r = parsers[name](a[i]); r.line = a[i]; out.push(r); }
  logs[name] = out;
  if (name === curlog) { fillkinds(); drawlog(); }
  if (name === "ioc") drawchart();
}
function loadlog(name) {
  if (full[name]) return;
  fetchdata(name + ".htm", function (text) { if (!full[name]) storelog(name, text); });
}
function loadlogs() {
  loadlog(curlog);
  if (curlog !== "ioc") loadlog("ioc");
}
function daynum(y, m, d) { return Math.floor(Date.UTC(y, m, d) / 86400000); }
function datetoday(s) {
  var m = /^([A-Z][a-z]{2}) +(\d{1,2}) (\d{4})/.exec(s || ""), mon = m ? monthnames.indexOf(m[1]) : -1;
  return mon < 0 ? null : daynum(parseInt(m[3], 10), mon, parseInt(m[2], 10));
}
function daylabel(n) { var t = new Date(n * 86400000); return monthnames[t.getUTCMonth()] + " " + ("0" + t.getUTCDate()).slice(-2); }
function kindslot(tag) {
  for (var i = 0; i < chartkinds.length - 1; i++) if (chartkinds[i][0] === tag) return i;
  return chartkinds.length - 1;
}
function svgel(tag, attrs, text) {
  var e = document.createElementNS("http://www.w3.org/2000/svg", tag), k;
  for (k in attrs) e.setAttribute(k, attrs[k]);
  if (text !== undefined) e.textContent = text;
  return e;
}
function chartscale(max) {
  var base = Math.pow(10, Math.floor(Math.log(Math.max(max, 1)) / Math.LN10)), mult = [1, 2, 5, 10], i, step = base;
  for (i = 0; i < mult.length; i++) { step = mult[i] * base; if (step * 2 >= max) break; }
  step = Math.max(step, 1);
  return step;
}
function chartrow(box, color, text) {
  var r = make("div"), k = make("i");
  k.style.background = color;
  r.appendChild(k);
  r.appendChild(document.createTextNode(text));
  box.appendChild(r);
}
function showtip(day, x) {
  var tip = byid("c_tip"), i, total = 0;
  clearnode(tip);
  for (i = 0; i < day.c.length; i++) total += day.c[i];
  tip.appendChild(make("b", "", daylabel(day.n) + ": " + total + (total === 1 ? " alert" : " alerts")));
  for (i = 0; i < day.c.length; i++) if (day.c[i]) chartrow(tip, chartkinds[i][2], chartkinds[i][1] + ": " + day.c[i]);
  tip.style.display = "block";
  tip.style.left = Math.min(x, byid("c_plot").clientWidth - tip.offsetWidth - 4) + "px";
}
function drawchart() {
  var today = datetoday(routerdate), days = [], seen = [], a = logs.ioc, i, j, n, r, total = 0, max = 0;
  var box = byid("c_plot"), legend = byid("c_legend"), W = 712, H = 130, L = 30, T = 14, B = 18, plot = H - T - B, slot = (W - L) / recentdays;
  clearnode(box); clearnode(legend);
  if (today === null) { var t = new Date(); today = daynum(t.getUTCFullYear(), t.getUTCMonth(), t.getUTCDate()); }
  for (i = 0; i < recentdays; i++) days.push({ n: today - recentdays + 1 + i, c: [0, 0, 0, 0, 0, 0] });
  for (i = 0; i < a.length; i++) {
    r = a[i];
    n = r.when ? datetoday(r.when) : null;
    if (n === null || n < days[0].n || n > today) continue;
    j = kindslot(r.tag);
    days[n - days[0].n].c[j]++;
    seen[j] = true;
    total++;
  }
  put("c_sub", total ? total + (total === 1 ? " alert" : " alerts") + " in " + recentdays + " days" : "");
  if (!total) { box.appendChild(make("div", "plain off", "No alerts in the last " + recentdays + " days.")); return; }
  for (i = 0; i < chartkinds.length; i++) if (seen[i]) chartrow(legend, chartkinds[i][2], chartkinds[i][1]);
  for (i = 0; i < days.length; i++) { days[i].t = 0; for (j = 0; j < 6; j++) days[i].t += days[i].c[j]; if (days[i].t > max) max = days[i].t; }
  var step = chartscale(max), top = Math.ceil(max / step) * step, svg = svgel("svg", { viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": total + " alerts in the last " + recentdays + " days, per day and kind" }), tip = make("div", "tip");
  for (i = 0; i <= top; i += step) {
    var gy = T + plot - plot * i / top;
    svg.appendChild(svgel("line", { x1: L, x2: W, y1: gy, y2: gy, stroke: i ? "#2c333a" : "#3b434c", "stroke-width": 1 }));
    svg.appendChild(svgel("text", { x: L - 6, y: gy + 3, "text-anchor": "end" }, String(i)));
  }
  var peakdone = false;
  for (i = 0; i < days.length; i++) {
    var x = L + i * slot + (slot - 24) / 2, y = T + plot, last = -1;
    for (j = 0; j < 6; j++) if (days[i].c[j]) last = j;
    for (j = 0; j < 6; j++) {
      if (!days[i].c[j]) continue;
      var h = Math.max(plot * days[i].c[j] / top - 2, 2), rad = j === last ? Math.min(4, h) : 0;
      y -= h;
      svg.appendChild(svgel("path", { fill: chartkinds[j][2], d: "M" + x + " " + (y + h) + "V" + (y + rad) + "Q" + x + " " + y + " " + (x + rad) + " " + y + "H" + (x + 24 - rad) + "Q" + (x + 24) + " " + y + " " + (x + 24) + " " + (y + rad) + "V" + (y + h) + "Z" }));
      y -= 2;
    }
    if (days[i].t === max && !peakdone) { peakdone = true; svg.appendChild(svgel("text", { x: x + 12, y: y - 1, "text-anchor": "middle", "class": "peak" }, String(max))); }
    if ((recentdays - 1 - i) % 3 === 0) svg.appendChild(svgel("text", { x: x + 12, y: H - 4, "text-anchor": "middle" }, daylabel(days[i].n)));
  }
  for (i = 0; i < days.length; i++) (function (day, sx) {
    var hit = svgel("rect", { x: sx, y: T, width: slot, height: plot, "class": "hit" });
    hit.onmousemove = function () { showtip(day, Math.round((sx + slot) * box.clientWidth / W)); };
    hit.onmouseout = function () { tip.style.display = "none"; };
    svg.appendChild(hit);
  })(days[i], L + i * slot);
  tip.id = "c_tip";
  box.appendChild(svg);
  box.appendChild(tip);
}
function fillkinds() {
  var sel = byid("l_kind"), keep = sel.value, seen = {}, a = logs[curlog], i, o;
  clearnode(sel);
  o = make("option", "", "All kinds"); o.value = ""; sel.appendChild(o);
  for (i = 0; i < a.length; i++) if (a[i].tag && !seen[a[i].tag] && curlog !== "reputation") {
    seen[a[i].tag] = 1;
    o = make("option", "", a[i].tag); o.value = a[i].tag; sel.appendChild(o);
  }
  sel.value = seen[keep] ? keep : "";
}
function addlink(box, label, url) {
  var a = make("a", "", label);
  a.setAttribute("href", url);
  a.setAttribute("target", "_blank");
  a.setAttribute("rel", "noopener noreferrer");
  box.appendChild(a);
}
function addlinks(box, indicator) {
  var v = trim((indicator || "").replace(/^.*->/, ""));
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) {
    addlink(box, "OTX", "https://otx.alienvault.com/indicator/ip/" + v);
    addlink(box, "AbuseIPDB", "https://www.abuseipdb.com/check/" + v);
    addlink(box, "URLhaus", "https://urlhaus.abuse.ch/host/" + v + "/");
  } else if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(v)) {
    addlink(box, "OTX", "https://otx.alienvault.com/indicator/domain/" + v);
    addlink(box, "URLhaus", "https://urlhaus.abuse.ch/host/" + v + "/");
    addlink(box, "ThreatFox", "https://threatfox.abuse.ch/browse.php?search=ioc%3A" + v);
  } else if (/^([a-f0-9]{32}|[a-f0-9]{64})$/i.test(v)) {
    addlink(box, "URLhaus", "https://urlhaus.abuse.ch/browse.php?search=" + v);
  }
}
function loghits() {
  var q = byid("l_find").value.toLowerCase(), kind = byid("l_kind").value, sev = curlog === "ioc" ? byid("l_sev").value : "", a = logs[curlog], hits = [], i, r, txt;
  for (i = 0; i < a.length; i++) {
    r = a[i];
    txt = (r.raw || [r.when, r.sev, r.tag, r.main, r.sub, r.rep, r.intel].join(" ")).toLowerCase();
    if (kind && r.tag !== kind) continue;
    if (sev === "critical" && r.sev !== "critical") continue;
    if (sev === "warning" && r.sev !== "critical" && r.sev !== "warning") continue;
    if (q && txt.indexOf(q) < 0) continue;
    hits.push(r);
  }
  if (byid("l_sort").value === "old") hits.reverse();
  return hits;
}
function csvtime(s) {
  var m = /^([A-Z][a-z]{2}) +(\d{1,2}) (\d{4}) (\d{2}:\d{2}:\d{2})/.exec(s || ""), mon = m ? monthnames.indexOf(m[1]) : -1;
  return mon < 0 ? s : m[3] + "-" + ("0" + (mon + 1)).slice(-2) + "-" + ("0" + m[2]).slice(-2) + " " + m[4];
}
function csvcell(v) {
  v = v === undefined || v === null ? "" : String(v);
  if (/^\s*[=+\-@]/.test(v) || /^[\t\r]/.test(v)) v = "'" + v;
  return /[",\r\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
}
function csvblank(v) { return /^(n\/a|\?\?|never|no flags|no categories)$/.test(v) ? "" : v; }
var csvlogs = {
  ioc: {
    head: ["timestamp_local", "type", "severity", "client", "indicator", "source", "detail", "abuseipdb_ip", "abuseipdb_score", "abuseipdb_reports", "abuseipdb_users", "abuseipdb_detail", "astraea_verdict", "astraea_reason"],
    row: function (r) {
      var c = /^([0-9A-Fa-f:.]+)->(.+)$/.exec(r.indicator), m = /^(?:TEST )?AbuseIPDB (\S+) (\d+)% (\d+)r\/(\d+)u ?(.*)$/.exec(r.rep);
      var v = /^Astraea (\w+): (.*)$/.exec(r.intel || "");
      return [csvtime(r.when), r.tag, r.sev, c ? c[1] : "", c ? c[2] : r.indicator, r.source, r.detail].concat(m ? m.slice(1) : r.rep ? ["", "", "", "", r.rep] : ["", "", "", "", ""], v ? [v[1], v[2]] : ["", ""]);
    }
  },
  dropbear: {
    head: ["timestamp_local", "username", "source_ip", "source_port", "process_id", "message"],
    row: function (r) {
      var u = /attempt for '(.*)' from /.exec(r.main), a = /from (\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s*$/.exec(r.main), p = /dropbear\[(\d+)\]/.exec(r.main);
      return [csvtime(r.when), u ? u[1] : "", a ? a[1] : "", a ? a[2] : "", p ? p[1] : "", r.main];
    }
  },
  hash: {
    head: ["timestamp_local", "path", "md5", "sha1", "sha256", "result", "matched_hash", "source", "family"],
    row: function (r) {
      var p = parts(r.line), n = p.length, h = /md5=(\S*) sha1=(\S*) sha256=(\S*)/.exec(p[n - 2]), m = /^MATCH: hash=(\S*) source=(.*) family=(.*)$/.exec(p[n - 1]);
      return [csvtime(r.when), p.slice(1, n - 2).join(" | "), h ? csvblank(h[1]) : "", h ? csvblank(h[2]) : "", h ? csvblank(h[3]) : "", m ? "match" : "no match", m ? m[1] : "", m ? m[2] : "", m ? m[3] : ""];
    }
  },
  reputation: {
    head: ["timestamp_local", "ip", "status", "score", "reports", "users", "last_report", "country", "usage_type", "isp", "flags", "categories", "trigger", "not_checked_reason"],
    row: function (r) {
      var p = parts(r.line), c;
      if (r.score === undefined) return [csvtime(r.when), trim(p[1]), "not checked", "", "", "", "", "", "", "", "", "", p.slice(3).join(" | "), p[2].replace(/^not checked: /, "")];
      c = /^(\d+) reports\/(\d+) users$/.exec(p[3] || "");
      return [csvtime(r.when), trim(p[1]), "checked", r.score, c ? c[1] : "", c ? c[2] : "", csvblank((p[4] || "").replace(/^last /, "")), csvblank(p[5]), p[6], csvblank(p[7]), csvblank(p[8]), csvblank(p[9]), p.slice(10).join(" | "), ""];
    }
  }
};
function csvtext(name, hits) {
  var spec = csvlogs[name], lines = [spec.head.concat("unparsed_line").join(",")], blanks = spec.head.map(function () { return ""; }), i, r;
  for (i = 0; i < hits.length; i++) {
    r = hits[i];
    lines.push((r.raw ? blanks.concat(r.raw) : spec.row(r).concat("")).map(csvcell).join(","));
  }
  return "\ufeff" + lines.join("\r\n") + "\r\n";
}
function csvname(name) {
  var d = new Date(), z = function (n) { return ("0" + n).slice(-2); };
  return "iocmon-" + name + "-" + (full[name] ? "full" : "recent") + "-" + d.getFullYear() + z(d.getMonth() + 1) + z(d.getDate()) + "-" + z(d.getHours()) + z(d.getMinutes()) + z(d.getSeconds()) + ".csv";
}
function downloadcsv() {
  var hits = loghits(), a, url;
  if (!hits.length) return;
  url = URL.createObjectURL(new Blob([csvtext(curlog, hits)], { type: "text/csv;charset=utf-8" }));
  a = document.createElement("a");
  a.href = url;
  a.download = csvname(curlog);
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
}
function drawlog() {
  var box = byid("l_rows"), a = logs[curlog], hits = loghits(), i, r, row, top, pages, end, lk;
  byid("l_csv").className = hits.length ? "btn" : "btn dis";
  pages = Math.max(1, Math.ceil(hits.length / pagesize));
  if (curpage >= pages) curpage = pages - 1;
  end = Math.min(hits.length, (curpage + 1) * pagesize);
  clearnode(box);
  for (i = curpage * pagesize; i < end; i++) {
    r = hits[i];
    row = make("div", r.sev ? "entry " + r.sev : "entry");
    if (r.raw) { row.appendChild(make("div", "main mono", r.raw)); box.appendChild(row); continue; }
    top = make("div", "top");
    top.appendChild(make("span", "when num", r.when));
    if (r.sev) top.appendChild(make("span", r.sev === "critical" ? "tag bad" : r.sev === "warning" ? "tag warn" : "tag off", r.sev));
    top.appendChild(make("span", r.bad || r.score >= 75 ? "tag bad" : r.score >= 25 ? "tag warn" : "tag", r.tag));
    row.appendChild(top);
    row.appendChild(make("div", "main mono", r.main));
    if (r.sub) row.appendChild(make("div", "sub", r.sub));
    if (r.rep) row.appendChild(make("div", "sub", r.rep));
    if (r.intel) row.appendChild(make("div", "sub", r.intel));
    lk = make("div", "links");
    addlinks(lk, r.indicator);
    if (lk.firstChild) row.appendChild(lk);
    box.appendChild(row);
  }
  if (!hits.length) box.appendChild(make("div", "plain off", a.length ? "Nothing matches this filter." : full[curlog] ? "Nothing logged yet." : "Nothing logged in the last " + recentdays + " days."));
  put("l_count", hits.length + " of " + a.length + " rows, " + (full[curlog] ? (a.length >= fullrows ? "newest " + fullrows + " of the full history" : "full history") : (a.length >= recentrows ? "newest " + recentrows + " in " : "last ") + recentdays + " days"));
  put("l_page", "Page " + (curpage + 1) + " of " + pages);
  byid("l_prev").className = curpage > 0 ? "" : "dis";
  byid("l_next").className = curpage < pages - 1 ? "" : "dis";
}
function picklog(name) {
  var names = ["ioc", "dropbear", "hash", "reputation"], i;
  curlog = name; curpage = 0;
  for (i = 0; i < names.length; i++) byid("tab_" + names[i]).className = names[i] === name ? "sel" : "";
  byid("l_kind").value = "";
  byid("l_sev").value = "";
  byid("l_sev").style.display = name === "ioc" ? "" : "none";
  byid("l_find").value = "";
  fillkinds(); drawlog(); drawfull(); loadlog(name);
}
function turn(step) {
  var next = curpage + step;
  if (next < 0) return;
  curpage = next; drawlog();
}
function loadfs() {
  var names = ["fsnew", "fsmod", "fsdel", "fsperm"];
  fetchdata("fssummary.htm", function (text) {
    var box = byid("fs_rows"), a = text ? datalines(text) : [], i, m;
    clearnode(box);
    for (i = 0; i < names.length; i++) put("l_" + names[i], "");
    for (i = 0; i < a.length; i++) {
      m = /^\[([1-4])\] (.*)$/.exec(a[i]);
      if (m) put("l_" + names[m[1] - 1], m[2]);
      else box.appendChild(make("div", "plain", a[i]));
    }
    if (!a.length) box.appendChild(make("div", "plain off", "No scan has run yet."));
  });
  for (var n = 0; n < names.length; n++) if (byid("d_" + names[n]).open) loadlist(names[n]);
}
function loadlist(name) {
  fetchdata(name + ".htm", function (text) {
    var box = byid("x_" + name), a = text ? datalines(text) : [], i;
    clearnode(box);
    for (i = a.length - 1; i >= 0; i--) box.appendChild(make("div", "mono", a[i]));
    if (!a.length) box.appendChild(make("div", "off", "Nothing listed."));
  });
}
function initial() {
  try { show_menu(); } catch (e) { if (window.console) console.error("IOCMON: show_menu failed", e); }
  document.form.current_page.value = window.location.pathname.substring(1);
  put("f_ver", pagever);
  lastchange = Date.now();
  poll();
  postaction("iocmonautocheck");
  setInterval(poll, 15000);
}
</script>
</head>
<body onload="initial();" class="bg">
<div id="TopBanner"></div>
<div id="Loading" class="popup_bg"></div>
<iframe name="hidden_frame" id="hidden_frame" src="" width="0" height="0" frameborder="0"></iframe>
<form method="post" name="form" action="start_apply.htm" target="hidden_frame" onsubmit="return false;">
<input type="hidden" name="current_page" value=""/>
<input type="hidden" name="next_page" value=""/>
<input type="hidden" name="modified" value="0"/>
<input type="hidden" name="action_mode" value=""/>
<input type="hidden" name="action_wait" value=""/>
<input type="hidden" name="first_time" value=""/>
<input type="hidden" name="action_script" value=""/>
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% nvram_get("preferred_lang"); %>"/>
<input type="hidden" name="firmver" value="<% nvram_get("firmver"); %>"/>
<table class="content" align="center" cellpadding="0" cellspacing="0">
<tr>
<td width="17">&nbsp;</td>
<td valign="top" width="202">
<div id="mainMenu"></div>
<div id="subMenu"></div>
</td>
<td valign="top">
<div id="tabMenu" class="submenuBlock"></div>
<table width="98%" border="0" align="left" cellpadding="0" cellspacing="0">
<tr>
<td align="left" valign="top">
<table width="760px" border="0" cellpadding="5" cellspacing="0" bordercolor="#6b8fa3" class="FormTitle" id="FormTitle">
<tr>
<td bgcolor="#4D595D" colspan="3" valign="top">
<div id="ioc">

<div class="hdr" id="hdr">
  <div class="dot"></div>
  <div><div class="state" id="h_state">LOADING</div><div class="sub" id="h_sub">Reading IOCMON status...</div></div>
  <div class="right"><b>IOCMON <span id="h_ver"></span></b><br/><span id="h_router"></span><br/><span id="h_uptime"></span></div>
</div>
<div class="banner red" id="b_alert" style="display:none"><span id="b_alert_t"></span><a class="btn ack" id="a_ack" onclick="acknowledge();">Acknowledge</a></div>
<div class="banner amber" id="b_update" style="display:none"><span id="b_update_t"></span><a class="btn ack" onclick="installupdate();">Install Update</a></div>
<div class="banner amber" id="b_page" style="display:none"></div>

<div class="actions" id="actions">
  <a class="btn" onclick="runaction('iocmonfeeds');">Update Feeds</a>
  <a class="btn" onclick="runaction('iocmonscan');">Scan Filesystem</a>
  <a class="btn" onclick="runaction('iocmonsimulate');">Simulate Detection</a>
  <a class="btn" onclick="runaction('iocmoncheck');">Check for Update</a>
  <a class="btn" id="a_iocmonstart" style="display:none" onclick="runaction('iocmonstart');">Start Monitor</a>
</div>
<div class="job" id="jobline"></div>

<div class="tiles">
  <div class="tile"><div class="k">Indicators</div><div class="v num" id="t_feeds">-</div><div class="s" id="t_feedsub"></div></div>
  <div class="tile"><div class="k">Alerts today</div><div class="v num" id="t_today">-</div><div class="s" id="t_level"></div></div>
  <div class="tile"><div class="k">Last alert</div><div class="v small num" id="t_last">-</div></div>
  <div class="tile"><div class="k">Reputation</div><div class="v small num" id="t_rep">-</div></div>
</div>

<div class="panel"><h2>Watches</h2><div class="grid">
  <div class="row"><span class="k">conntrack</span><span class="v" id="w_conn">-</span></div>
  <div class="row"><span class="k">dns</span><span class="v" id="w_dns">-</span></div>
  <div class="row"><span class="k">auth</span><span class="v" id="w_auth">-</span></div>
  <div class="row"><span class="k">dns log</span><span class="v off" id="w_dnslog">-</span></div>
  <div class="row"><span class="k">nvram</span><span class="v" id="w_nvram">-</span></div>
  <div class="row"><span class="k">fs-integrity</span><span class="v" id="w_fs">-</span></div>
</div></div>

<div class="panel"><h2 class="split">Feed sources<span class="fcols num"><span class="fi">Indicators</span> | <span class="fu">Last Updated</span></span></h2><div id="f_rows"></div></div>

<div class="panel"><h2>System</h2><div class="grid">
  <div class="row"><span class="k">Email</span><span class="v" id="s_email">-</span></div>
  <div class="row"><span class="k">Cron</span><span class="v" id="s_cron">-</span></div>
  <div class="row"><span class="k">Storage</span><span class="v" id="s_storage">-</span></div>
  <div class="row"><span class="k">Drive free</span><span class="v" id="s_free">-</span></div>
  <div class="row"><span class="k">Router time</span><span class="v" id="s_time">-</span></div>
  <div class="row"><span class="k">Scan interval</span><span class="v" id="s_loop">-</span></div>
</div></div>

<div class="panel"><h2>Filesystem integrity</h2>
  <div class="bad plain" id="fs_err" style="display:none"></div>
  <div id="fs_rows" class="mono"></div>
  <div class="plain mono" id="l_fsnew"></div>
  <details id="d_fsnew" ontoggle="if(this.open)loadlist('fsnew');"><summary>New Files</summary><div class="list" id="x_fsnew"></div></details>
  <div class="plain mono" id="l_fsmod"></div>
  <details id="d_fsmod" ontoggle="if(this.open)loadlist('fsmod');"><summary>Modified Files</summary><div class="list" id="x_fsmod"></div></details>
  <div class="plain mono" id="l_fsdel"></div>
  <details id="d_fsdel" ontoggle="if(this.open)loadlist('fsdel');"><summary>Deleted Files</summary><div class="list" id="x_fsdel"></div></details>
  <div class="plain mono" id="l_fsperm"></div>
  <details id="d_fsperm" ontoggle="if(this.open)loadlist('fsperm');"><summary>Permission Changes</summary><div class="list" id="x_fsperm"></div></details>
</div>

<div class="panel"><h2 class="split">Activity, last 14 days<span class="fcols num" id="c_sub"></span></h2>
  <div class="legend" id="c_legend"></div>
  <div class="chartbox" id="c_plot"></div>
</div>

<div class="panel"><h2>Logs</h2>
  <div class="tabs">
    <a id="tab_ioc" class="sel" onclick="picklog('ioc');">IoC Detections</a>
    <a id="tab_dropbear" onclick="picklog('dropbear');">Dropbear</a>
    <a id="tab_hash" onclick="picklog('hash');">Hash-Check</a>
    <a id="tab_reputation" onclick="picklog('reputation');">Reputation</a>
  </div>
  <div class="tools">
    <input type="text" id="l_find" placeholder="Search" maxlength="80" autocomplete="off" oninput="curpage=0;drawlog();"/>
    <select id="l_kind" onchange="curpage=0;drawlog();"></select>
    <select id="l_sev" onchange="curpage=0;drawlog();"><option value="">All severities</option><option value="warning">Warning and Critical</option><option value="critical">Critical only</option></select>
    <select id="l_sort" onchange="curpage=0;drawlog();"><option value="new">Newest first</option><option value="old">Oldest first</option></select>
    <a class="btn" id="l_full" onclick="togglefull();">Full History</a>
    <a class="btn dis" id="l_csv" title="Downloads every row matching this search and these filters in the order shown, not just this page. Use Full History first for older rows." onclick="downloadcsv();">Download CSV</a>
  </div>
  <div id="l_rows"></div>
  <div class="pager"><a id="l_prev" onclick="turn(-1);">&lt; Prev</a><span><span id="l_page"></span> | <span id="l_count"></span></span><a id="l_next" onclick="if(this.className!=='dis')turn(1);">Next &gt;</a></div>
</div>

<div class="foot">IOCMON web interface v<span id="f_ver"></span>. Updates every 15 seconds.</div>
</div>
</td>
</tr>
</table>
</td>
</tr>
</table>
</td>
<td width="10" align="center" valign="top">&nbsp;</td>
</tr>
</table>
</form>
<div id="footer"></div>
</body>
</html>
