<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<!-- IOCMON-WebUI v1.6.4 -->
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
#ioc #b_alert, #ioc #b_update, #ioc #b_auth { align-items: center; gap: 12px; }
#ioc #b_alert_t, #ioc #b_update_t, #ioc #b_auth_x { flex: 1; min-width: 0; }
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
#ioc #b_auth b { display: block; color: #fff; letter-spacing: 1px; }
#ioc .auth .aok { color: var(--green); }
#ioc .auth .abad { background: var(--red); color: #fff; padding: 0 3px; }
#ioc .auth .awarn { color: var(--amber); }
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
#ioc .xshow { margin-left: 10px; padding: 2px 10px; background: var(--button); border-bottom: 1px solid var(--cyan); color: var(--text) !important;
              cursor: pointer; text-decoration: none; letter-spacing: 1px; font-size: 11px; text-transform: uppercase; }
#ioc .xshow:hover { background: var(--buttonhover); }
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
#ioc .cleartools { display: flex; justify-content: flex-end; padding-top: 8px; }
#ioc .cleartools .btn { flex: none; padding: 4px 8px; font-size: 10px; }
#ioc .entry .links { display: flex; align-items: center; flex-wrap: wrap; }
#ioc .xsw { margin-left: auto; display: inline-flex; align-items: center; gap: 6px; cursor: pointer; font-size: 11px; color: var(--dim) !important; text-decoration: none; }
#ioc .xsw .knob { position: relative; width: 26px; height: 12px; background: var(--button); border-radius: 6px; }
#ioc .xsw .knob:after { content: ""; position: absolute; top: 2px; left: 2px; width: 8px; height: 8px; border-radius: 4px; background: var(--dim); }
#ioc .xsw.on { color: var(--green) !important; }
#ioc .links a.xsw { color: var(--dim) !important; margin-right: 0; }
#ioc .links a.xsw.on { color: var(--green) !important; }
#ioc .xsw.on .knob { background: #1f5a3c; }
#ioc .xsw.on .knob:after { left: 16px; background: var(--green); }
#ioc .xsw.wait { opacity: 0.6; cursor: default; }
#ioc .excitem { display: flex; align-items: center; gap: 8px; padding: 3px 0; border-bottom: 1px solid #2c333a; }
#ioc .excitem .mono { flex: 1; min-width: 0; overflow-wrap: anywhere; font-size: 11px; }
#ioc .excitem .excip { flex: 0 0 140px; }
#ioc .excitem .excnote { flex: 1; min-width: 0; overflow-wrap: anywhere; color: var(--dim); }
#ioc .modal { position: fixed; left: 0; top: 0; right: 0; bottom: 0; background: rgba(0, 0, 0, 0.55); display: flex; align-items: center; justify-content: center; z-index: 9999; }
#ioc .modal .mbox { background: var(--panel); border-left: 4px solid var(--cyan); padding: 14px 16px; width: 460px; max-width: 90%; overflow-wrap: anywhere; }
#ioc .modal .mt { font-weight: 600; margin-bottom: 8px; }
#ioc .modal .mwarn { color: var(--red); margin-top: 8px; }
#ioc .modal .mbtns { display: flex; gap: 8px; justify-content: flex-end; margin-top: 12px; }
#ioc .modal .mbtns .btn { flex: none; min-width: 90px; }
#ioc .btn.tvbtn { flex: 1.3; background: linear-gradient(100deg, #0f4a55, #173a44); border-bottom-color: var(--cyan); color: #bff6ff !important; font-weight: 600; }
#ioc .btn.tvbtn:hover { background: linear-gradient(100deg, #146271, #1d4955); }
#ioc .tv { position: relative; }
#ioc .tvbar { display: flex; align-items: center; gap: 8px; }
#ioc .tvbar .btn { flex: none; padding: 6px 10px; }
#ioc .tvtitle { color: var(--cyan); font-size: 15px; font-weight: 600; letter-spacing: 4px; margin-left: 6px; text-shadow: 0 0 8px rgba(47, 208, 228, .55); }
#ioc .tvclock { margin-left: auto; color: var(--dim); font-size: 11px; white-space: nowrap; }
#ioc .tvclock b { color: var(--text); font-weight: 400; }
#ioc .tvstage { position: relative; margin-top: 8px; background: radial-gradient(ellipse at 50% 40%, #13232b 0%, #0b1115 70%); border: 1px solid #1d2a31; overflow: hidden; }
#ioc .tvstage canvas { position: absolute; left: 0; top: 0; display: block; }
#ioc .tvstage::after { content: ""; position: absolute; left: 0; right: 0; top: 0; bottom: 0; pointer-events: none;
                       background: repeating-linear-gradient(0deg, rgba(255, 255, 255, .018) 0, rgba(255, 255, 255, .018) 1px, transparent 1px, transparent 3px); }
#ioc .tvmsg { position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); max-width: 80%; text-align: center; color: var(--cyan);
              background: rgba(11, 17, 21, .82); border: 1px solid #1d4955; padding: 10px 14px; z-index: 3; display: none; }
#ioc .tvnote { position: absolute; left: 8px; bottom: 6px; color: var(--amber); font-size: 11px; z-index: 3; display: none; background: rgba(11, 17, 21, .8); padding: 2px 6px; }
#ioc .tvreplaytag { position: absolute; left: 50%; top: 8px; transform: translateX(-50%); color: var(--amber); border: 1px solid var(--amber); background: rgba(11, 17, 21, .8);
                    padding: 2px 10px; letter-spacing: 2px; font-size: 11px; z-index: 3; display: none; }
#ioc .tvlegend { position: absolute; right: 8px; bottom: 6px; display: flex; gap: 10px; font-size: 10px; color: var(--dim); z-index: 3; background: rgba(11, 17, 21, .7); padding: 2px 6px; }
#ioc .tvlegend i { display: inline-block; width: 16px; height: 0; border-top: 2px solid; vertical-align: middle; margin-right: 4px; }
#ioc .tvtip { position: absolute; z-index: 4; display: none; background: rgba(15, 21, 26, .95); border: 1px solid #1d4955; border-left: 3px solid var(--cyan);
              padding: 7px 10px; font-size: 11px; width: 300px; max-height: 260px; overflow: auto; }
#ioc .tvtip .tt { font-weight: 600; color: var(--text); display: flex; justify-content: space-between; align-items: center; gap: 8px;
                  position: sticky; top: -7px; z-index: 1; margin: -7px -10px 4px -10px; padding: 7px 22px 4px 10px; background: rgb(15, 21, 26); }
#ioc .tvtip .tt a { color: var(--dim) !important; cursor: pointer; text-decoration: none; font-size: 13px; line-height: 1; padding: 2px 5px; }
#ioc .tvtip .tt a:hover { color: var(--text) !important; }
#ioc .tvtip .ip { padding: 3px 0; border-top: 1px solid #2c333a; }
#ioc .tvtip .ip .links a { margin-right: 8px; }
#ioc .tvcounts { display: grid; grid-template-columns: repeat(7, 1fr); gap: 6px; margin-top: 8px; }
#ioc .tvcounts div { background: var(--panel); padding: 5px 7px; min-width: 0; clip-path: polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 0 100%); }
#ioc .tvcounts .k { color: var(--dim); font-size: 9px; letter-spacing: .3px; text-transform: uppercase; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
#ioc .tvcounts .v { font-size: 19px; line-height: 1.2; }
#ioc .tvcounts .v small { font-size: 10px; color: var(--dim); margin-left: 2px; }
#ioc .tvcounts .off .v { font-size: 11px; line-height: 11.5px; min-height: 23px; color: var(--dim); white-space: normal; }
#ioc .tvcounts .off .v small { display: none; }
#ioc .tvfilters { display: flex; flex-wrap: wrap; gap: 4px 14px; margin-top: 8px; align-items: center; color: var(--dim); font-size: 11px; }
#ioc .tvfilters label { cursor: pointer; white-space: nowrap; }
#ioc .tvfilters input { vertical-align: middle; margin: 0 4px 0 0; }
#ioc .tvalert { margin-top: 8px; display: none; align-items: center; gap: 12px; }
#ioc .tvpanel { margin-top: 8px; }
#ioc .tvfeed { max-height: 260px; overflow: auto; }
#ioc .tvrow { display: grid; grid-template-columns: 58px 30px 66px 108px 26px 70px 1fr 34px; gap: 6px; padding: 2px 4px; border-bottom: 1px solid #262d33;
              font-size: 11px; cursor: pointer; align-items: baseline; }
#ioc .tvrow:hover { background: var(--panel2); }
#ioc .tvrow.tvhead { position: sticky; top: 0; z-index: 1; background: var(--panel); color: var(--dim); font-size: 10px; letter-spacing: .5px; text-transform: uppercase; cursor: default; }
#ioc .tvrow .res { cursor: help; }
#ioc .tvkey { color: var(--dim); font-size: 10px; margin-top: 4px; }
#ioc .tvkey b { color: var(--text); font-weight: 600; }
#ioc .tvrow span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
#ioc .tvrow .n { text-align: right; color: var(--dim); }
#ioc .tvrow.blk { color: var(--dim); }
#ioc .tvrow.critical { color: var(--red); }
#ioc .tvrow.warning { color: var(--amber); }
#ioc .tvtop { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
#ioc .tvtop h3 { color: var(--dim); font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase; margin: 0 0 4px 0; font-weight: 600; }
#ioc .tvbarrow { position: relative; display: flex; justify-content: space-between; padding: 2px 6px; margin-bottom: 2px; font-size: 11px; }
#ioc .tvbarrow i { position: absolute; left: 0; top: 0; bottom: 0; background: rgba(47, 208, 228, .16); }
#ioc .tvbarrow span { position: relative; }
#ioc .tvreplay { display: flex; flex-direction: column; gap: 8px; }
#ioc .tvreplay input[type=range] { width: 100%; }
#ioc .tvreplay .tools { margin-bottom: 0; }
#ioc .tvfoot { color: var(--dim); font-size: 10px; margin-top: 8px; display: flex; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
#ioc .tvfoot a { color: var(--cyan) !important; cursor: pointer; }
#ioc .tv .fsonly { display: none; }
#ioc .tv.full { position: fixed; left: 0; top: 0; right: 0; bottom: 0; z-index: 9000; background: var(--bg); padding: 10px 12px 4px 12px; display: flex; flex-direction: column; }
#ioc .tv.full .fsonly { display: inline-block; }
#ioc .tv.full .tvbar { flex: none; }
#ioc .tv.full .tvstage { flex: 1; min-height: 0; }
#ioc .tv.full .tvside { flex: none; }
#ioc .tv.full .tvfoot { flex: none; margin-top: 6px; }
#ioc .tvdrawbtn { display: none; }
#ioc .tv.full .tvpanel { position: absolute; left: 0; bottom: 34px; height: 46%; width: min(620px, 52%); margin: 0; z-index: 5; display: flex; flex-direction: column;
                         background: rgba(21, 27, 32, .95); border: 1px solid #1d4955; border-left: 0; padding: 8px 10px; transform: translateX(-100%); transition: transform .25s ease; }
#ioc .tv.full.drawer .tvpanel { transform: none; }
#ioc .tv.full .tvpanel .tabs { flex: none; }
#ioc .tv.full .tvfeed, #ioc .tv.full #tvp_top, #ioc .tv.full #tvp_replay { flex: 1; min-height: 0; max-height: none; overflow: auto; }
#ioc .tv.full .tvdrawbtn { display: block; position: absolute; left: 100%; top: 50%; transform: translateY(-50%); writing-mode: vertical-rl; padding: 12px 5px; cursor: pointer;
                           background: #0f4a55; border: 1px solid var(--cyan); border-left: 0; color: #bff6ff !important; font-size: 11px; letter-spacing: 2px; text-decoration: none; }
#ioc .tv.full .tvdrawbtn:hover { background: #146271; }
@media (prefers-reduced-motion: reduce) { #ioc .tv.full .tvpanel { transition: none; } }
@media (max-width: 700px) { #ioc .tvcounts { grid-template-columns: repeat(3, 1fr); } }
#ioc .tvcal { position: absolute; left: 0; top: 0; right: 0; bottom: 0; z-index: 20; background: radial-gradient(ellipse at 50% 45%, #03140a 0%, #010603 75%); cursor: pointer;
            overflow: hidden; opacity: 1; transition: opacity .8s; font-family: "Courier New", Courier, monospace; animation: tvcalflicker 5s infinite; }
#ioc .tvcal.out { opacity: 0; animation: none; }
#ioc .tvcal canvas { position: absolute; left: 0; top: 0; display: block; }
#ioc .tvcal::after { content: ""; position: absolute; left: 0; right: 0; top: 0; bottom: 0; pointer-events: none;
                   background: repeating-linear-gradient(0deg, rgba(0, 0, 0, .28) 0, rgba(0, 0, 0, .28) 1px, transparent 1px, transparent 3px),
                               radial-gradient(ellipse at 50% 50%, transparent 60%, rgba(0, 0, 0, .55) 100%); }
#ioc .tvcalterm { position: absolute; left: 6%; top: 7%; right: 4%; color: #39ff6a; text-shadow: 0 0 6px rgba(57, 255, 106, .65); line-height: 1.25;
                letter-spacing: 1px; font-weight: bold; }
#ioc .tvcalrow { white-space: pre; min-height: 1.25em; }
#ioc .tvcalrow.cur::after { content: ""; display: inline-block; width: .6em; height: 1em; margin-left: 2px; vertical-align: -2px; background: #39ff6a;
                          animation: tvcalblink 1s steps(1) infinite; }
#ioc .tvcalterm .inv { background: #39ff6a; color: #011a07; text-shadow: none; }
#ioc .tvcalhint { position: absolute; right: 10px; bottom: 6px; color: rgba(57, 255, 106, .5); font-size: 10px; letter-spacing: 2px; z-index: 1; }
@keyframes tvcalblink { 50% { opacity: 0; } }
@keyframes tvcalflicker { 0%, 100% { opacity: 1; } 48% { opacity: 1; } 50% { opacity: .96; } 52% { opacity: 1; } }
@media (prefers-reduced-motion: reduce) { #ioc .tvcal, #ioc .tvcalrow.cur::after { animation: none; } #ioc .tvcal { transition: none; } }
@media (max-width: 700px) { #ioc .tiles { grid-template-columns: 1fr 1fr; } #ioc .grid { grid-template-columns: 1fr; } }
</style>
<script type="text/javascript">
var pagever = "1.6.4", datapath = "/ext/iocmon/", lastts = "", lastchange = 0, routerage = null, lastlogkey = "";
var logs = { ioc: [], dropbear: [], hash: [], reputation: [] }, curlog = "ioc", curpage = 0, pagesize = 10;
var job = { id: "", state: "" }, waiting = null, jobchain = false, jobstale = false, updateinfo = null, acktimer = null, updatelatest = "";
var exc = {}, excpend = {}, askdone = null, curexc = "dns";
var lognames = { ioc: "IoC Detections", dropbear: "Dropbear", hash: "Hash-Check", reputation: "Reputation" };
var exclists = [["dns", "DNS Domains", "DNS exceptions"], ["ip", "IP Addresses", "IP/CIDR exceptions"], ["file", "Files", "excluded files"], ["cron", "Cron Entries", "cron exceptions"]];
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
  showauth(d);

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

  var failover = d.dnsstate === "adguardhome" || d.dnsstate === "pihole" ? d.dnsfailover : "0";
  var dnsname = d.dnsstate === "pihole" ? "Pi-hole" : "AdGuard Home";
  setrow("w_conn", onoff(d.conntrackon === "1", plural(d.conntrackchecked || "0", "dst ip") + ", checked " + (d.conntracklast || "n/a")));
  if (d.dnsstate === "off") setrow("w_dns", { t: "off", c: "v off" });
  else if (d.dnsstate === "waiting") setrow("w_dns", { t: "awaiting query-log setup", c: "v warn" });
  else if (d.dnsstate === "nologin") setrow("w_dns", { t: "skipped, AdGuard Home login missing", c: "v warn" });
  else if (failover === "2") setrow("w_dns", { t: dnsname + " not answering, last checked " + (d.dnslast || "n/a"), c: "v warn" });
  else setrow("w_dns", { t: (failover === "1" ? (d.dnsstate === "pihole" ? "Pi-hole, one unreadable, " : "AdGuard Home backup, ") : d.dnsstate === "adguardhome" || d.dnsstate === "pihole" ? dnsname + ", " : "") + (d.dnschecked || "0") + " checked at " + (d.dnslast || "n/a"), c: failover === "1" ? "v warn" : "v on" });
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

function authword(st) {
  var w = { ok: ["ok", "aok"], bad: ["invalid", "abad"], unsigned: ["unsigned", "abad"], noossl: ["unchecked", "awarn"], nokey: ["no key", ""], off: ["off", ""] };
  return w[st] || ["pending", ""];
}

function showauth(d) {
  var h = byid("h_auth"), s = authword(d.sig_script), p = authword(d.sig_page), badscript, badpage, restored, showrest, t;
  badscript = d.sig_script === "bad" || d.sig_script === "unsigned";
  badpage = d.sig_page === "bad" || d.sig_page === "unsigned";
  restored = !badscript && !!d.sig_restored;
  showrest = restored && d.sig_restored_ack !== "1";
  if (restored) s = ["restored", "abad"];
  clearnode(h);
  if (d.sig_script === undefined) { byid("b_auth").style.display = "none"; return; }
  h.appendChild(document.createTextNode("IOCMON Authenticity: script ["));
  h.appendChild(make("span", s[1], s[0]));
  h.appendChild(document.createTextNode("] | web ui ["));
  h.appendChild(make("span", p[1], p[0]));
  h.appendChild(document.createTextNode("]"));
  h.title = d.sig_script === "ok" ? "Signed " + (d.sig_signed || "at an unknown time") + ", key " + (d.sig_key || "?") + "..., checked " + (d.sig_checked || "n/a") : "";
  if (restored) h.title = (d.sig_restored_kind === "update" ? "Bad AMTM update replaced " : "Altered copy replaced ") + d.sig_restored + " - shown until IOCMON is restarted";
  byid("b_auth").style.display = badscript || badpage || showrest ? "flex" : "none";
  byid("a_authack").style.display = showrest ? "" : "none";
  if (!badscript && !badpage && !showrest) return;
  if (badscript || !showrest) {
    put("b_auth_h", badscript ? "AUTHENTICITY WARNING: This copy of IOCMON could not be authenticated and may have been altered." : "AUTHENTICITY WARNING: This IOCMON web page could not be authenticated and may have been altered.");
    put("b_auth_t", "Script: " + s[0] + " | Web UI: " + p[0] + ". Reinstall IOCMON from the official source: " + (d.sig_url || "the IOCMON GitHub page") + ". This warning can't be acknowledged; it clears once a correctly signed copy is installed.");
    return;
  }
  put("b_auth_h", "AUTHENTICITY WARNING: An altered copy of IOCMON was replaced with the last verified copy.");
  t = d.sig_restored_kind === "update" ? "An IOCMON update downloaded by AMTM on " + d.sig_restored + " failed its signature check, so the last verified copy (v" + (d.sig_restored_ver || "?") + ") was put back."
    : "Found " + d.sig_restored + ". IOCMON v" + (d.sig_restored_ver || "?") + " from the last verified copy is running, and any edits to iocmon.sh were undone.";
  if (badpage) t += " The web page could not be authenticated either (Web UI: " + p[0] + ") - reinstall IOCMON from " + (d.sig_url || "the IOCMON GitHub page") + ".";
  put("b_auth_t", t + " Acknowledge hides this warning; the Authenticity status keeps showing [restored] until IOCMON is restarted.");
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
  put("a_authack", "Acknowledging...");
  postaction("iocmonack");
  clearTimeout(acktimer);
  setTimeout(poll, 2000);
  acktimer = setTimeout(function () { poll(); put("a_ack", "Acknowledge"); put("a_authack", "Acknowledge"); }, 6000);
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
  var p = parts(line), rep = "", intel = "", sev = "", xc = "", n;
  if (/^exc:[0-9a-f]{8}$/.test(p[p.length - 1])) xc = p.pop().slice(4);
  if (/^sev:(critical|warning|info)$/.test(p[p.length - 1])) sev = p.pop().slice(4);
  if (p.length < 5) return { raw: line };
  n = p.length;
  if (/^Astraea (clear|confirm|unknown|contained): /.test(p[n - 1])) { intel = p[n - 1]; n--; }
  if (/^(TEST )?AbuseIPDB /.test(p[n - 1])) { rep = p[n - 1]; n--; }
  if (n < 5) return { raw: line };
  return { when: p[0], tag: p[1], main: p.slice(2, n - 2).join(" | "), sub: p[n - 2] + " - " + p[n - 1], rep: rep, intel: intel, indicator: p.slice(2, n - 2).join(" | "), source: p[n - 2], detail: p[n - 1], sev: sev, exc: xc };
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
  loadexc();
}
function loadexc() {
  fetchdata("exceptions.htm", function (text) {
    var a = text ? datalines(text) : [], m = {}, i, f, t;
    for (i = 0; i < a.length; i++) {
      f = a[i].split("|");
      if (f.length < 5 || !/^[0-9a-f]{8}$/.test(f[0])) continue;
      m[f[0]] = f[1] === "ip" ? { list: f[1], on: f[2] === "1", crit: f[3] === "1", value: f[4], note: f.slice(5).join("|") }
        : { list: f[1], on: f[2] === "1", crit: f[3] === "1", value: f.slice(4).join("|"), note: "" };
    }
    exc = m;
    for (t in excpend) if ((exc[t] ? exc[t].on : false) === excpend[t].on || Date.now() - excpend[t].at > 20000) delete excpend[t];
    if (curlog === "ioc") { fillkinds(); drawlog(); }
    drawexc();
  });
}
function excon(t) { return excpend[t] ? excpend[t].on : !!(exc[t] && exc[t].on); }
function exclabel(list) { var i; for (i = 0; i < exclists.length; i++) if (exclists[i][0] === list) return exclists[i][2]; return list; }
function askbox(title, text, warn, oklabel, done) {
  put("m_title", title); put("m_text", text); put("m_warn", warn || "");
  byid("m_warn").style.display = warn ? "block" : "none";
  put("m_ok", oklabel);
  askdone = done;
  byid("m_box").style.display = "flex";
}
function closeask() { askdone = null; byid("m_box").style.display = "none"; }
function okask() { var f = askdone; closeask(); if (f) f(); }
function sendexc(t, on) {
  excpend[t] = { on: on, at: Date.now() };
  postaction("iocmonexc" + (on ? "on_" : "off_") + t);
  drawlog(); drawexc();
  setTimeout(loadexc, 2500);
  setTimeout(loadexc, 7000);
}
function toggleexc(t) {
  var e = exc[t], what;
  if (!e || excpend[t]) return;
  if (excon(t)) { sendexc(t, false); return; }
  what = e.list === "dns" ? e.value + " and its subdomains" : e.value;
  askbox("Add an exception", "Add " + what + " to the " + exclabel(e.list) + "? IOCMON stops alerting on it from now on; rows already in the log stay.",
    e.crit ? "This is a startup script, SSH or router configuration file. IOCMON will no longer watch it for tampering: changes, deletion and permission changes to it will go unreported." : "",
    "Add exception", function () { sendexc(t, true); });
}
function excswitch(t) {
  var on = excon(t), e = exc[t], a = make("a", "xsw" + (on ? " on" : "") + (excpend[t] ? " wait" : ""));
  a.appendChild(make("span", "knob"));
  a.appendChild(make("span", "", "Exception"));
  a.setAttribute("title", on ? "In the " + exclabel(e.list) + ": " + e.value + ". Turn off to remove it." : "Add " + e.value + " to the " + exclabel(e.list));
  a.onclick = function () { toggleexc(t); };
  return a;
}
function excitems(list) {
  var items = [], t;
  for (t in exc) if (exc[t].list === list && (exc[t].on || excpend[t])) items.push(t);
  return items.sort(function (a, b) { return exc[a].value < exc[b].value ? -1 : exc[a].value > exc[b].value ? 1 : 0; });
}
function pickexc(list) { curexc = list; drawexc(); }
var excopen = false;
function excshowapply() {
  byid("x_body").style.display = excopen ? "" : "none";
  put("x_show", excopen ? "Hide" : "Show");
}
function toggleexcpanel() {
  excopen = !excopen;
  try { localStorage.setItem("iocmon_excshow", excopen ? "1" : "0"); } catch (e) { }
  excshowapply();
}
function drawexc() {
  var box = byid("x_lists"), g, i, items, row, n;
  for (g = 0; g < exclists.length; g++) {
    put("xtab_" + exclists[g][0], exclists[g][1] + " (" + excitems(exclists[g][0]).length + ")");
    byid("xtab_" + exclists[g][0]).className = exclists[g][0] === curexc ? "sel" : "";
  }
  clearnode(box);
  items = excitems(curexc);
  for (i = 0; i < items.length; i++) {
    row = make("div", "excitem");
    if (curexc === "ip") {
      row.appendChild(make("span", "mono excip", exc[items[i]].value));
      row.appendChild(make("span", "excnote", exc[items[i]].note || ""));
    } else row.appendChild(make("span", "mono", exc[items[i]].value));
    row.appendChild(excswitch(items[i]));
    box.appendChild(row);
  }
  if (!items.length) box.appendChild(make("div", "plain off", "No " + exclabel(curexc) + "."));
  for (i = 0, n = 0; i < exclists.length; i++) n += excitems(exclists[i][0]).length;
  put("x_total", n + (n === 1 ? " item" : " items"));
}
function clearlog() {
  var name = curlog;
  if (byid("l_clear").className.indexOf("dis") >= 0) return;
  askbox("Clear the " + lognames[name] + " log?", "This erases the whole " + lognames[name] + " log on the router, including rows older than this page shows and its rotated copies, for this page and the IOCMON screen alike.",
    "This can't be undone.", "Clear Log", function () {
      postaction("iocmonclear" + name);
      logs[name] = []; full[name] = false; curpage = 0;
      if (name === curlog) { drawfull(); fillkinds(); drawlog(); }
      if (name === "ioc") drawchart();
      setTimeout(loadlogs, 2500);
    });
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
  if (curlog === "ioc") { o = make("option", "", "Excepted only"); o.value = "__exc"; sel.appendChild(o); }
  sel.value = seen[keep] || (keep === "__exc" && curlog === "ioc") ? keep : "";
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
    if (kind === "__exc" ? !(r.exc && excon(r.exc)) : kind && r.tag !== kind) continue;
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
    head: ["timestamp_local", "type", "severity", "client", "client_name", "indicator", "source", "detail", "abuseipdb_ip", "abuseipdb_score", "abuseipdb_reports", "abuseipdb_users", "abuseipdb_detail", "astraea_verdict", "astraea_reason"],
    row: function (r) {
      var c = /^([0-9A-Fa-f:.]+)(?: \[([^\]]*)\])?->(.+)$/.exec(r.indicator), m = /^(?:TEST )?AbuseIPDB (\S+) (\d+)% (\d+)r\/(\d+)u ?(.*)$/.exec(r.rep);
      var v = /^Astraea (\w+): (.*)$/.exec(r.intel || "");
      return [csvtime(r.when), r.tag, r.sev, c ? c[1] : "", c ? c[2] || "" : "", c ? c[3] : r.indicator, r.source, r.detail].concat(m ? m.slice(1) : r.rep ? ["", "", "", "", r.rep] : ["", "", "", "", ""], v ? [v[1], v[2]] : ["", ""]);
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
  put("l_clear", "Clear " + lognames[curlog] + " Log", a.length ? "btn" : "btn dis");
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
    if (r.exc && exc[r.exc] && excon(r.exc)) top.appendChild(make("span", "tag off", "excepted"));
    row.appendChild(top);
    row.appendChild(make("div", "main mono", r.main));
    if (r.sub) row.appendChild(make("div", "sub", r.sub));
    if (r.rep) row.appendChild(make("div", "sub", r.rep));
    if (r.intel) row.appendChild(make("div", "sub", r.intel));
    lk = make("div", "links");
    addlinks(lk, r.indicator);
    if (r.exc && exc[r.exc]) lk.appendChild(excswitch(r.exc));
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
var tvmap = { cols: 288, rows: 105, step: 1.25, top: 75.0, mask: "AAAAAADw9wDz/wAA/P///wEAAAAAAAD4AADg//8HANAAAAAAAAAAAADwf9///wcA+P///wAAAAAAAAA8gBv//////wAHAAAAAwAAAAD4/58//38A+P//fwAAAAAAAAAewP////////b/AQCAA8D/AwAG/v88//8B8P//fwACAAD+AQD44Pv//////////wCAAPD///v/////+/0H8P//PwAAAMD/P8CI//v/////////////D/j/////////f+wf4P//AwAAAPD//5n///////////////////D/////////f+x/4P8/AAwAAPz///v///////////////////z/////////H/x34P8P4B8AAP7/D///////////////////MPz///////////4fwP8A4B8AAP/9////////////////////wPD///////9/+IAfgP8AAAMAwP/+////////////////////APj///////8/IH8WAH8AAAAE8D/+//////////////////8fAPz///////8fAP4RAD4AAABA8P/+////////////////H/8DAMD/gP////8fAP45AAAAAAAA8P/8////////////////jw8AAAA9APz///8/AP5/AAAAAAA8cH78//////////////8B4AcAAAA3APj/////A/x/AAAAAAB8wH////////////////8A8AcAAOABAOD/////P///AQAAAAB+wA/+/////////////z8A8BMAADAAAGD/////f///BwAAAID/gP////////////////8F8AMAAAAAAOD/////f///DwAAAAD3+/////////////////8H8AAAAgAAAAD+//////7/DwAAAAD3+/////////////////8HYAAAAAAAAAD+////////DQAAAAD4//////////////////8HAAAAAAAAAAD8//////8/HgAAAADA//////////////////8PAAAAAAAAAADw//////8fPwAAAADw//////////////////8GAAAAAAAAAADw////////KAAAAADA/////////////////38GAgAAAAAAAADw////////AAAAAACA/////X/+/////////38CAQAAAAAAAADw//////8/AQAAAACA//9/yD///////////x8uAAAAAAAAAADw//////8AAAAAAAD/P/9/AD/+/////////w8fAAAAAAAAAADw//////8AAAAAAAD+h55/Hn78/////////wEFAAAAAAAAAADw/////18AAAAAAAD+wbj////8/////////wADAAAAAAAAAADg/////x8AAAAAAAD/hrDn///8////////fgADAAAAAAAAAADg/////w8AAAAAAgD/ADz////4////////8YADAAAAAAAAAADA/////w8AAAAAAAB+/gnG////////////4+ABAAAAAAAAAADA/////wcAAAAAAADY/wEY9P//////////4PwBAAAAAAAAAACA/////wcAAAAAAAD8/wEA9P//////////4f4AAAAAAAAAAAAA/v///wEAAAAAAAD//w8H8P//////////AQ8AAAAAAAAAAAAA/P///wAAAAAAAAD//x8/+///////////AQMAAAAAAAAAAAAA+P//fwAAAAAAAAD/////////////////AwAAAAAAAAAAAAAA+P//6QAAAAAAAID//////3//////////AwAAAAAAAAAAAAAA8P8H4AAAAAAAAPj//////3/+////////gwAAAAAAAAAAAAAA8P8HwAAAAAAAAPD////////8////////AQAAAAAAAAAAAAAAwP8HwAQAAAAAAPD/////7//z////////AgAAAAAAAAAAAAAAwP4DAAIAAAAAAPj///////8/4P////9/AwAAAAAAAAAAAAAAgP0D4AkAAAAAAPj/////n///wP////8/AwAAAAAAAAAAAAAAAPgD8gcAAAAAAPz/////v///gP////8PAAAAAAAAAAAAAAAAAPiHBz4AAAAAAPz/////v/9/AP8//r8AAAAAAAAAAAAIAAAAAPiPA+ABAAAAAPj/////P/9/APwf+J8BAAAAAAAAAAAAAAAAAOD/A9QXAAAAAPj/////f/4/APwP+L8AAwAAAAAAAAAAAAAAAID/AwBAAAAAAPz///////4fAPwD+H8AAwAAAAAAAAAAAAAAAADuHwAAAAAAAPz///////wDAPwB2H+AAwAAAAAAAAAAAAAAAADAPwCAAAAAAPz///////8AAPgAwP8ABwAAAAAAAAAAAAAAAAAAHwAAAAAAAPz//////z8AAPgBwP8ADwAAAAAAAAAAAAAAAAAAHGABAAAAAPz//////wcBAPAAgPyAHgAAAAAAAAAAAAAAAAAAOPj/AAAAAPD///////8BAPAAwHiADgAAAAAAAAAAAAAAAAAA+Pv/AAAAAOD///////8BAOABwDBAHAAAAAAAAAAAAAAAAAAA4P7/AQAAAOD///////8BAOADwAAgPgAAAAAAAAAAAAAAAAAAAP7/AwAAAMD///////8AAAADgAMgOgAAAAAAAAAAAAAAAAAAAPz/PwAAAAD/8f///38AAAAAMAfwCQAAAAAAAAAAAAAAAAAAAPz/fwAAAAAG8P///38AAAAAcAd4IAAAAAAAAAAAAAAAAAAAAP7//wAAAAAAgP///z8AAAAA8AZ+AAAAAAAAAAAAAAAAAAAAAP7//wAAAAAAgP///x8AAAAAwI9/QAAAAAAAAAAAAAAAAAAAAP///wEAAAAAoP///wcAAAAAwI9/TwAAAAAAAAAAAAAAAAAAgP///wcAAAAAgP///wMAAAAAAI+/Rx8AAAAAAAAAAAAAAAAAgP///x8AAAAAgP///wMAAAAAgB+/W+4AAAAAAAAAAAAAAAAAgP////8BAAAAAP///wAAAAAAAH6f4/8HAwAAAAAAAAAAAAAAgP////8HAAAAAP7//wAAAAAAAByIB/gfBgAAAAAAAAAAAAAAgP////8PAAAAAP7//wAAAAAAADiAAcC/EwAAAAAAAAAAAAAAgP////8PAAAAAPz//wAAAAAAAPAHAIJ/MAAAAAAAAAAAAAAAAP////8PAAAAAPz//wAAAAAAAMD/NcJ3oQAAAAAAAAEAAAAAAP7///8PAAAAAPz//wAAAAAAAACgGQDnBAEAAAAAAAAAAAAAAP7///8HAAAAAPz//wEAAAAAAAAACQCGAQIAAAAAAAAAAAAAAPz///8DAAAAAPj//wEAAAAAAAAAAD8GBAAAYAAAAAAAAAAAAPz///8DAAAAAPz//8EAAAAAAAAAAD8GAAAAQAAAAAAAAAAAAPj///8BAAAAAP7//8EBAAAAAAAA8D8OAAAAAAAAAAAAAAAAAPj///8BAAAAAP7///EBAAAAAAAA+D8eACAAAQAAAAAAAAAAAOD///8BAAAAAP7///gAAAAAAAAA/v8fAEAAAAAAAAAAAAAAAID///8BAAAAAP7/P/gAAAAAAAAA/v8fAEBAAAAAAAAAAAAAAID///8BAAAAAPz/H/gAAAAAAAAA//9/AAAAAAAAAAAAAAAAAAD///8AAAAAAPz/D3hAAAAAAADw////ADgAAAAAAAAAAAAAAID//38AAAAAAPj/H3wAAAAAAAD4////ABAAAAAAAAAAAAAAAID//38AAAAAAPj/H3wAAAAAAAD4////AQAAAAAAAAAAAAAAAID//wcAAAAAAPj/HzgAAAAAAAD8////AwAAAAAAAAAAAAAAAID//wMAAAAAAPD/BxgAAAAAAAD4////BwAAAAAAAAAAAAAAAID//wEAAAAAAPD/BwAAAAAAAAD8////BwAAAAAAAAAAAAAAAID//wMAAAAAAPD/AwAAAAAAAAD4////BwAAAAAAAAAAAAAAAMD//wEAAAAAAOD/AwAAAAAAAAD4////BwAAAAAAAAAAAAAAAMD//wAAAAAAAOD/AQAAAAAAAADw////BwAAAAAAAAAAAAAAAMD/fwAAAAAAAMD/AAAAAAAAAADw////BwAAAAAAAAAAAAAAAMD/PwAAAAAAAMB/AAAAAAAAAADwD/j/AwAAAAAAAAAAAAAAAMD/PwAAAAAAAMAPAAAAAAAAAADwAPD/AQAAAAAAAAAAAAAAAOD/AwAAAAAAAAAAAAAAAAAAAAAAAMD/AQAMAAAAAAAAAAAAAOD/BwAAAAAAAAAAAAAAAAAAAAAAAID/AAAYAAAAAAAAAAAAAOD/AwAAAAAAAAAAAAAAAAAAAAAAAAD/AAB4AAAAAAAAAAAAAOD/AAAAAAAAAAAAAAAAAAAAAAAAAAAoAAB4AAAAAAAAAAAAAPA/AAAAAAAAAAAAAAAAAAAAAAAAAAB4AAA2AAAAAAAAAAAAAPAfAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAeAAAAAAAAAAAAAPAfAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAHBAAAAAAAAAAAAPAPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMADAAAAAAAAAAAAAPAHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOABAAAAAAAAAAAAAPgPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAAPgPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPgDAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAPgBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPiDAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAfAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  coast: "zBu`@CLNPb@JZAOUHS[OMGQASJHL cwAr@a@Le@JMHIHCJ_@JEHP@CLQJKTK??FMBDBUF@DL@BEPARCNKHKJOXINDJDANNDHATAPORCBDX?GOMEDUHOd@QN?\\SDHF@BG?GNIUEM?@E\\?FKPCFI[CIE_@FAFE^UJOUUKQ?QFMDUB kfAyAGGQIMMIOG?IHAFKDQD@FL?CHLFJPMP@HUPV@DL?PPL@RF\\@ETFFKLAHEVFFIL?NA@YHEHO@QAQKMMDOCCOGCWCMOIK ny@{m@JFZAVCII[CQDGD ry@mo@H?d@ABCg@?MB@@ n{@gp@WFBD\\BNCHG?GY@I? bv@om@^Ar@EFK@IRGh@ATGGGg@@UDg@?QFDDWDKB[?[@_@Cg@Aa@@SFEFLBZDXCx@Bh@? pdA{o@[BDDd@DZEOG[A jdAgp@YBVB^??CSCI? lh@qJI@CBBBN?J@?IAAO? no@qJM@IBCDL?DBJCHEAEG?C? lr@oMQ@O?QDGFSAEBQJKHE?KB@DO?MF@BLBJ?LA\\@MIFEJ?FEBKJ?PCDCXCFCGCRALHF?BDF@HAKECGGCICOACA va@a_@HJLPMGKDDDQDGESFDLMCAHGLHNF@LCCOBCVPJ?MIRCR?f@?@EKGFCOKS_@MKOEI?BD ls@ug@UDWD?HOAMFPD\\EJGRHZHFIX@OICOEQM?CHICKD fp@gl@SEk@H[FAHe@ESLo@FQFQPb@Ho@J]D]P]?DL`@VVG^SX@@JSJ[HGBKRDLXCp@O[NUJAFt@Gh@KVIEE\\IZI?Dx@BPGMMe@?g@CDEGIWSBGFG\\Ih@EMCTMP?NGHDb@BfAEj@E^ANGSGZ?DSOQSGs@ENJOLQOs@Ia@T@Je@E `z@im@i@?e@B\\PVBTNTAJO?IIISC v}@ml@TMUGWBc@CEDRH_@FBP`@FPALEp@O?Ei@@ jbAkn@QCS?CHJHbA@p@H\\?BEi@IxABZC[SQEw@Fc@Ja@?ZQQGU@EHGF xkAqn@a@Oi@K]?[A@LNFP?d@F^BZC |jAom@[Bq@?SDUFXDn@LXL?Fr@HHGl@KGGMMQMRKcAA `gBwd@O@AFJ@JALESC v~Agc@K@IDPHRFHEBIQEKC |qAw`@SADTONF?JGDIJE@I?EIB jmAg^IHSFGJH@`@GDGPE@ETCDI?EUBKBQ@GD hjB{f@KBKAODS@@@LBNCFCP@BAAG |`Aqp@g@@u@FMHGF^A^El@ASEVC@G qScUO?QELHABRFHABGI?AE mOaU@D\\@?CVCCGIDO?O?@BKA }]xFEFELAVEF@HBDDKBDCN@FDB@PFTHZJd@FZFTNDPFJENEBI@QFO?MAOIA?GIMAMDGBM?QEIAMI?KCGCG?KKOKEI@GG@IMAKEIEH ogB|HKJD@DG?E ggBxHBE?OIDCNDAB@ {rAhC@OCECGCD?HHL sfBdLOJIHFBHELGLKJMBEI?IFIDED k~AhAGDAHDDBKBGFEJILECCKDEBGBGH q}ArBHDJBH?NEJEAEQBIACIA?AHK?EGIE@KKACB?JDJH@BB idBpEEDL?FKKBC@ adB~DBBLQBKE?GNGH qcBdEF?LABCAGMBEBCD wbB~CED?BNGHEFGCAGDOF eaBjCGDB@FCFG?CKF w_BhBEDGJID@DD@FGHKBOCAAD qmB`XFHHLNF@EFAIODKTGAGMEAO?KFM?CHGLQHMG?KHMDEPMRAMGDCNODK@KGI@BPDJNADDAH@B aiBfZOKKIIMEECIMICFCFOGCF?HDFLNHFGHN?NDDLJRNHHBP?JETABEIOYSKCOE i{AnXK@AVFD@NDELLB?LAJO@MJO?IM@SDIAOC ymAbSRHPDBHDFP?J@PCL@L@JHD?HBHFLAL?RKJC?KIACC?GAM@KHSBK?IFM?EFGBOHOBGIFFQIDEF?IHO@EBEAKCCAI@KGMALGMQEGGOGIAC@OEKACEE?I?UEIIEIIIAG?IMQGPICFIEIIBAMIIEGIC?EG@?CIAICMHKJK?K@BKIOGC@EGKKEI@QC?INEKCKDKFOBEAKDKCG?CAIHDHFFD?AFDHFHADOJODIDMJE?IDCDQDMECKCGAKEO@G?E@KCOAC@ECICK?EGEEHAJC@AFEHAJ?FELMEEFIF@FCPAHE@EP@HELUHMHKF@BKLGRGCGHCCCTMJIFONCNAH@LIN@PBHBP?HBLFRNFFNDHDPFHBLBLADJFT?PFHFJFNGJCAIHBPLPEHAJAREJKBOBIHGRAEIBMHLPBKKAKGI@MNPJDFNNG?KJMHGCCXKL?RIb@@XDTFRA cr@uCBRFDPBFOB[G_@MHILIT {oAv@UDENNIN?J?L?CKY? inAjALCBGSACFDD }nAk@AJK@AF@NHA@LGHD@FKDYCOEG ykAQW?SMABNRLBRC^?PBBLQPKGc@G?HHCFJPFSXBDQV?JJDFEIORFBEAGLKASLDAV?ZJBFEEQBSF?DMGMAMI_@CGQMODW@ ejAlEXMQCIDGD@BF@ yjAhDM?QG@H\\DZA?GOCKD }hAfDKACFTBL@J?GIIAEEGD ybA~BAFe@@EGc@FGL]BWJTFTIP@TAPCVGLAFBb@GBIP?MSW@ODG@ g`ATALGHM@ILBV@^T?NQXOFKNOHMN[NQDOFOPMHONKRU@IK@_@BQPMLKFQTU?OLKNMHFNKFG? ojA}FHOQ@EDBPHI skAgECEAKK?BJOQ@PFDDLDDJMCE _nAgDAJ?JDPFSFHENDFVKDMEIJGDFHALJBEGOKEKGEHOECIM?@OOHAHAF mcAkJNE@QIGUEK?CFFFDJNH ckAgNJ^HNHO@OKQOOIDBJ uwAoWPR?TFNCHHLXFb@@ZTLE?Ob@BTHV?SNL^JHHGCQJEFMSEIKSIMMg@EUBSc@MH]SIGMWBWGKUCIZ?N kyAoZMGCTZDPR^MHTT?BSIMUAE[EOUTODMB mDqXIEKL@XH?FDFE?WBKI@ mDsYMGCNFNFCDMCE wFab@EHJNTK@G]E rAsc@W?TRSAU?BNPPS@SXM@KVEFWB@JHDEHNHZ?`@DHCJHPALDJC]SQC^CDGUEJICM]@CKLKVCDEGGDEJH?SHIESOOO? `Hqh@BLULXLx@LPBXAv@GSGj@Ic@C?Eh@CKM_@A]L]KYD_@Ia@? ixAq`@GR@PGTU`@\\EJZQT?LNKJLBOAS@UCMA[JQA[QIFGICCL aiAyDXPIMMKKMISCNLJHL mkAkJ@FELBNJFBNCNK@GAYH@JEB@HNIFKBFLKPBHEAGECDE@FHKBG?SGFA_@EQK?KDEEAD gkAcF@IKDK??FHHJD?I?I mmAsFEVNE?DEJHD?MDABKK@?GJOQ@ED jo@mDK@MMGA?GCOKIK?ACO@OIGEGGG?EDBD@DH@EF?JHHGNG?EOFE?OWG@GGGELM@MH?DQ@UAIFO@KE?CWAW?NDEHO?OHANI?GBMFKL?HG?KHGDWBACO?SBGBMBUNAFG@CFKb@IBALNNEDc@@?ROKWDa@LIHBJWEe@H]?]NYTMDQ?GFEVCJF`@HJZZLVLND@DLAd@D\\@LDFBXRX@RPHBJT?\\FNFTDTNPR@LAJBRBHLHTb@PNLFFRLJFJTJNCH@PIL@JK@HYPBLMF@HPX\\Hf@BTACJBNCHJDTBPGFDARMDIGEJPDNJ@RDHP?NJDLSLSBFPVJJVPFFFETMHH?P?FBPFBPF@VGTMVI to@oCGHCPBBCPBJGDFHFJH@DDAHF@ADJFJBAFFLBJDBAPBBKHGICHHLNJDLIRDFMFMLGLGHQf@Sb@OX@DGNOLc@Te@RAFSHC\\A^Dj@Dh@Bd@JXAVDNE\\H\\L^J^F@ATERHJDd@DZKBEYMDHh@VGD`@PN]DTNFRA`@IJDJGL tm@~_@QB[LYFIIEMSGM@EHKLYLYBFHP@JGDFNDH?JANERAXKRIZW _[kq@g@C]?CDKEQA]BFBX@P@@@VBTCKGl@? m`@am@o@QDIm@IaAMaAAa@Gg@AMFLDfAHz@F|@R\\R^PCPe@NJ@~@CDGb@E@ISC@Kg@OPA cPaq@\\Jx@@x@CBCZATG}@E[BSEq@Dg@D mNuo@j@Hb@EMCJGi@CGF[B mHyp@GE]AYF_ALp@FHNPBHNV?h@KQE\\Ef@QNOw@EID[? to@oCDEBKCCBABEHEH@BDFDB?@BIJD@@@H@BK@BDABGFADAB?B?@B@AHCBEAA?EDCFCDA@EDCADBBBCFA@C?EAG@?@ACCFEFGBEHGHGACCBAABE@?BA@DJADAHCH?DCHCJ?HCHGVUHENEJ@NDH@LCLCPINATIPGBEJAREFGTKHKBIEA@ECE?EDI@GDIPSRMHMPG@CAKHEJIBMJ?JKFI@EHMFOAGNGD@JE@FAHALGFMLCDA?CFA?CJEDEDKHEREFEH?HI?GHGF?BHF@?DKJKNIHCAOBIHELI@BBELCJKAAG@GG?ILMJEFKFKFOFQBIJKHA@EJADCRABC@KRSN[?CHELQBOHICO?QDOGQAQAQB[DODIAC]FIPEEBODOB?d@SLGb@GJQAKVIBOVM?IJGPEDQVOJQPA^?VEh@SPCb@GZ@d@IVGTBCLJ@TBPDTBBIISUEDEXJLJZLMHPNTFRDDF\\HDHVFL?PBRFPD`@D@CUGQEUKWAIG[KCCOGAMKKVDDCJFJIDDFIRFJ?@KCEJGXBPIJC@KLGGKOIEIOAM@OGO?MEBGHCMGJ?TBDDLE\\BZEFGXK[Gk@IO?@Hi@?NKVGLIRGZGKIc@?WIEISGSAe@IQ@]K]DOFGCa@@@B_@BSAi@De@@O@YC]DUBe@B_@HS@QGWE]@]G_@EMFMCEIM@_@P[MANWCGEW@_@Fm@F[BSAYHZHc@Bu@AQCSJUIRGKGW?OAQBSJUAa@H_@C]?BKQC_@F?PKOO?ISTKVGAUWMY@SH[TPHe@B@R[OWLDLQLUMMQAU[@]@YHAHNJMH@Hd@LZ@TEDHPPDFVLZ@NF@JTBXNRTFN@V]@GRIL[Ce@FSFMHWDUF_@@U@@NERMT]ROEIUH]LK_@GUMKM@MLQVMWUHQD]MEa@DS@QCQDWJEFc@??PEVQBOJ[KSUKGOPYVUVFLYHQJ_@DMDGNMBGDAVLDLF`@DVP`@@j@C\\?R@NLXF\\ZTPOCa@Yg@O]AQHPJETENYHa@CSUALKFVJl@JPFVNLA@Qc@O^?TBADRHTDRDHJBB?JEHG?@EEB@DJ@H?NBF?J@ND]CEBZDL??CDDE@BLLN@EB?DECHCB?FDFHN@AEKHGBQ@HCJLAMD?PE@ADCRLNRDLJH?HF@DTLJHFJBLCLENIL?HGT?L?FDJD@HA@GFEHOHOBGCKBKNOFCRHBAHIJCT@PAN@F@CD?FCBB@FAFBL?LKP@LCJ@PBPNRFHHDF?LAHCDFPBL@Z@HCHEHCNMLCJGHUBGHQEMAOCKCKGEK?OCEMEUCO?K?EB?HJHBLC@BHBLDCB??@C@?BBHA@@FA@BHBB@@BDEBACEBA?CCE?A@A?I?I?EAAAE?E@C?CAI@A@EBEBG@ED@@@BAFBD@F@HAB?H@@@F?DBBADABA@CFGFIF pr@_EEF?BG?A?EBIAGCKCEEK?@@K@GBGDEB xk@iKACC?K?KDC?CDK?@DI?IFFFHCF?F?@BF?BCD@FLDC?CLCF@LAFBJEAGSBM@GEHG?GJACEK?QB gHyVMADNADBHNGHAZICIU@UA mV}ZWFYP wqA}SIKKBGIMDCDJJFEHBDJJE?I dI}J@IAIBIJGAG?IGEEI?EEMKMEAEK?IGMKEMSIGQAOMIEOOBYGOAKKKSIOGMSEMM?KHSASBG?SIUCKGSEa@C_@AIBSGS?GBM?UGM@?HOGABHH?HEB@PLHCHK?CHGBWDGAOBYFIPQB[FUHICIIDOEGOIKA[BEFG?EBS@EDY?SDSDG@OEGEQAMBEHCGODO?ICEE@AEICMAEGOIM@OCGDIGGJ@PCLJ\\@NITABFLBRKT?JSLIIOJIUQ]AGMe@@WKWEa@?a@L[FWCQ@WIAIBKJGJADEXQVGNIMCOOHG[G?EPBN@JDR@ND?JIDSABFTBXHJCCGREACSGDC^C?GR@DJNL?DHBDABVJFDLEJAFQDBBV@FDNHFGACLAH?VBMJH@J?HIBBCJKHFBIHID?HPCEHJ@GPL?NGFOBMFIHI?EBA?CJG@GAMAE@CBADEFCREJGPENMCAHG?GJADFDE?GCANANDAH@DEHQHINUNO?EDDBQDMDQHABBFJINAHJOF@HH@HNF@?ECKCCFIDIFCDGJCHGLANGPMLIDSHANGHBHFH@PJd@E\\D@J?JPLXB@DJJFNGJJFBLLBLLX?R?JFFFHADGDIRCFDHCH@CO@KHABEAMGG?GCK?GBE?G?MFG[MW@[?UBOA_@@IKCg@RUNI\\G@MYCa@DDWQHm@OEOQCOCIEQ][GO?CCO?CBMIBG@KFI?SCECEQAGCOE@HDDCDI@BFDANLEH?FUB@FUCIEUFIDME_@GWGSBADS?CI[EBO?OIKQGONO?COAKD@LE@KYEYASBUAUIRIb@@b@D^DJKRECSFQGKQKm@UMC@GZI`@DRLCJ^Nf@PLZMLSHPTTDF`@HPVAJNV?DQNUN]JKf@VZBXIFUDm@QKu@Qe@Se@[o@e@_@Ow@Wk@I_@@]Oe@?c@C}@LXDUJSEa@Ju@BkAVOF?LTH^DxAOLB_@LAH?RYDODAIJIMEo@JOEJMm@SQ@QDKMNKIKLKw@FIHV@?JMD_@CCKoB[O@RJY@KEe@A]GUJWKTKKEy@D[DgATMIRI@EVAGGJO?Ec@QMQMCu@BCJRNMDELBZUJHLd@ZU@GEUEEIQIJIGMTABIOSXOc@MBMIAIJFRU@HMa@Gi@?c@JPQ@Sa@Eq@@i@ANKWKU?g@Is@CECu@AOBk@Ie@?CISGo@Ga@DZDm@@CHSCy@?k@HOFBHTDr@HNDWB]BQCILIE_@C_ABCHsA@AMi@@_@?_@JIJJFWN_@FSS_@Fa@Ee@FMEa@@NQ[GsDJQJs@NoACg@@OF@NWD[Cc@Ac@Bg@Aa@PWENMIG}@Di@Ay@H[F ooBsg@XHXAQHKNIDAFDDb@Cv@LP@\\L\\LFFZMr@NHGPHZCDLVRAFUB@ZR@FNGF`@JFT\\BDTZPFMF]Jk@I[QK?G_@Ec@Wa@Sc@OO]V@JPr@TNYr@Fp@^OLj@B\\@?M\\CXHz@A`AD~@d@lAn@_@@IJSBKIU@[TAPNR@VF^\\ZFLXVZTJJZJJ?JIZL@FFAFFDD?LHBBBFDJBHB?H@@G@IHQVEJ?VFHPBNFP@@ICOHSOCLOHC@@D@@CB?DCEGCC@AEK@CJAFCZDNFRDIIBGOKJINDVLJJR@HHKJOB?HOBUMQFM?AJZBHJPHHLSHGRKPMN?NJBCJKDBNBNJ@LRNZPVZPZNT@JHFEJFZHRBDN@DH?DMEGZEF@ZPNPBLMTSXQJKNGd@@`@NLVJNPVPFKEMNKNAFKHSPGP?COP?@TH\\DN?NM?GPCPIHKBIHE@KJGJ?L@HADAJGDEP?DL@POVO@IJK@QFIAMBIFEBIHKHIBJ@KAKEQ@OEMFKAUFIDWBYFOLHTLJAJCEYBQNWCEJCLODI@IBIFKP?AFDJHC@@DAFA@FL?VB?NHHZLVVLJRL?FHDPDH@DNCXANFP?`@J@FNEDPDFJFDPQH[FSDIHQDYBKP[Fe@DY?WBSZJLAXWGGDETQNCDOLMd@B^?Z@d@ETCTAFYHAN@RHVEROREJQNYH@LEDFJACH@BELGPIBCFMF?F@FADEDCDAB@MEIEAED?JBJCFCA?DOCO?K@MMMKMMEEA@@F@BANGLKDMBK@IJEDEB?BFJ@DFDFLHABD@HAJ@BH?JD@HBBJ?FD?FHBJ?JDH?LDBH?DRF^HPLH@DAHFLBN@D?BDD?@DH?D@L?DKAKBEBMDGCA@GAC?GBIDE?GHEJQDOLMFALS@MAKJUHGHCDK?CDIDCFOJOHMH?CI?GCG@ADFBNBHDBDGHGL]@@GTKRO^GHEJQTB@?LWPCBERBBARGVGBIFKVEPIH[PIJKJEDIDCD?FJDGBGBCFGHI?SESAQEIAGCI?G?GCKAGEG??D@H?JBDBTHTJXP\\PTTXRP\\PRNTVBHBDLFDFD@BLDFBJFFHVAJKDADDJAD@HEJGRGBCH@RCN?^CHDLFLJJRFTHTTF@LNFB@LINCH?DC?@R@FCB@FHFNDVJFDAFC@@HBN@NDHLHB@FHDHHLVTLJLFTFH@@BJAHBTCJ@F?TFN@JFH?FEDAHG?@BCAKFMEC?MJSHONYLOFMBSDMD]?W@KFGHOJWBMNQ@O@KCQEQAIEQCGKKEIAM?KDEDKBK?CEGDSBMHKAC@EDONSRSLQJS?ECEEOCMBCEUCOFKHCBIBA?ERFFAFDNAHKFMLML?P?NBNB^JJDPDPEF?LCJ?VBLDRFBAD?RGPOPIJMDALGHIBG@MHKFGBADC@I@CDAJIF?BE?CDC@C@OAGFOHEGCIMCI?KCICQBS ~mBsi@n@O noB`ICA@H@@ umAfDM?GAE@DDTFNDLLND@CAEGKSGACOE noBcj@o@Nu@R@JMDDOu@Bg@PRH^@@PFBP?NEXEBIRAV@HECGVBIHJF noBuk@AAQ?[D@BRBX@ ooBgk@T?BEYG ooBjIJBLB@GICE?KE fe@j_@WKODKGOHBDZDFGPHHI aj@j]MDQBABDF^@?KCG?C inB|IECED@JL@HA@IGEG@ pe@wEKAC??NP@BAEE?G b`BqKC@A@EFFDD@BBBC?CBGAAAC?C?AA@G@ n`B_L@BD?BC@AAAE@E@ ~`BgL?@H??AI? vaBqLA?CF@?D?BC?AEA rbB{LABB@DCA?AAC? zo@wNE?GP?HD@BKFECK jp@wOIAM@?BTB@G ro@{OOFBLBAAIHG?A ~f@k\\EFOBQ?HFF?VGDEGE e\\{ZSSQCIKQCWGOBSACLBPNAPB?LRA?DKDGPWDCFDFABELAOOCEHMJNFREBPM?DLODBTCL@B\\D\\CLIPCDM?IECCGCOOADCHAHMHITWAMPQ hg@e^EAYDUF?BH?XEPI dq@ye@GEG?CBFJFADEAA ns@af@MG[??BVHL?BE ~m@ci@LDT?BIGIQCOD?F@B j{@qj@SJLDXEN@ZGQEMGSBKB paAul@UFKRELa@Hc@H@F^@KFDDb@Ab@ET@d@Dp@Bb@@JIXEP@VOKA_@A[?YCd@Cj@@Z?HGm@G^?`@EOMMGu@KSBHFm@EYHWIQFOPIGLSQAS@ zp@ol@TIAGGAm@@c@J?DRAT?TBDA mvA{l@QGYA[FAD\\?h@A@A s{Aan@q@BTF^Ad@GEEc@B wuAqn@u@?gAHNNhA?^Bf@MIKYC r|@{n@AAOF?JHL^@TC?I^?@MU?]E[? g_Aqp@s@JDFpBFe@YOAM? sy@sq@i@Eg@Jm@PDPh@@v@C`@GNMXCs@M ~z@kq@MESAFCm@AYJaAFOJWFZDb@Lb@@h@ATIAEOEd@?TEJIMG fx@er@]CW?e@C]GW@UDOKYAc@A}@AI@y@Ai@?k@@u@@i@@e@D@Bn@Hp@BPBk@?l@J`@D`@Nf@BLBz@@[@LBOHPD^DHFZDCBa@??Bt@Jr@Ex@B\\Ad@A@Ic@CHMMAs@HXM`@COGc@CEEZGFKu@@O@_@Gl@AdA@b@GNGVEBE f\\sr@cAKeA?YEeAA_D@}BNd@FjA?jB@IBeAA}@De@EOFTHs@E_BG{@BKFpALHB~@Bm@@VLNJ?VWJ\\@`@De@HCPT?YPj@@WFFDZBZ?YL?Ff@GHD[BYJEN`@BNGVIEJVJu@?[@t@Nt@Nz@FT?RFZRj@LJ@ZBZBPL?LHJ^NGNHNHRZ@\\Qf@?PILS`@WHMBQZQGMLGSW]EGGCOTDJBP@VE@MGIS?g@B`@KPER@NEUQJGNKVUXG?Gt@Kh@At@@n@?VE`@Ks@Eg@ArACl@GAGkAIiAIGGt@EOGeAM]AHIo@C}@C}@?UDs@Io@D[@i@Dn@IAG raA_m@Y?OBPJ\\MEA",
  countries: "ZW|29.9|-18.9|1.2|Zimbabwe;ZM|26.4|-14.7|1.8|Zambia;YE|45.9|15.3|1.5|Yemen;VN|105.4|21.7|1.7|Vietnam;VE|-64.6|7.2|2.1|Venezuela;VA|12.5|41.9|0.3|Vatican;VU|166.9|-15.4|0.8|Vanuatu;UZ|64.0|41.7|2.0|Uzbekistan;UY|-56.0|-33.0|0.8|Uruguay;FM|158.2|6.9|1.7|Micronesia;MH|171.2|7.1|0.9|Marshall Is.;MP|145.7|15.2|0.3|N. Mariana Is.;VI|-64.8|17.7|0.3|U.S. Virgin Is.;GU|144.7|13.4|0.3|Guam;AS|-170.7|-14.3|0.3|American Samoa;PR|-66.5|18.2|0.3|Puerto Rico;US|-97.5|39.5|3.0|United States of America;GS|-31.1|-55.7|1.2|S. Geo. and the Is.;IO|71.3|-6.2|0.3|Br. Indian Ocean Ter.;SH|-5.7|-16.0|1.4|Saint Helena;PN|-128.3|-24.4|0.3|Pitcairn Is.;AI|-63.0|18.2|0.3|Anguilla;FK|-58.7|-51.6|0.3|Falkland Is.;KY|-81.2|19.3|0.3|Cayman Is.;BM|-64.8|32.3|0.3|Bermuda;VG|-64.6|18.4|0.3|British Virgin Is.;TC|-71.8|21.8|0.3|Turks and Caicos Is.;MS|-62.2|16.7|0.3|Montserrat;JE|-2.1|49.2|0.3|Jersey;GG|-2.6|49.5|0.3|Guernsey;IM|-4.5|54.2|0.3|Isle of Man;GB|-2.1|54.4|1.7|United Kingdom;AE|54.5|23.5|0.7|United Arab Emirates;UA|32.1|49.7|1.9|Ukraine;UG|32.9|2.0|0.9|Uganda;TM|58.7|39.9|1.7|Turkmenistan;TR|34.5|39.3|1.8|Turkey;TN|9.0|33.7|0.9|Tunisia;TT|-60.9|11.0|0.3|Trinidad and Tobago;TO|-175.2|-21.2|0.3|Tonga;TG|1.1|8.8|0.5|Togo;TL|125.9|-8.8|0.4|Timor-Leste;TH|101.1|15.5|1.8|Thailand;TZ|35.0|-6.1|1.8|Tanzania;TJ|72.6|38.2|1.0|Tajikistan;SY|38.3|35.0|1.0|Syria;CH|7.5|46.7|0.5|Switzerland;SE|19.0|65.9|2.2|Sweden;SZ|31.5|-26.5|0.3|eSwatini;SR|-55.9|4.1|0.7|Suriname;SS|30.4|7.2|1.6|S. Sudan;SD|29.3|16.3|2.5|Sudan;LK|80.7|7.6|0.5|Sri Lanka;ES|-3.5|40.1|3.0|Spain;KR|128.1|36.4|0.9|South Korea;ZA|23.7|-29.7|3.0|South Africa;SO|45.2|3.6|2.0|Somalia;SB|159.2|-8.0|1.3|Solomon Is.;SK|19.0|48.7|0.5|Slovakia;SI|14.9|46.1|0.4|Slovenia;SG|103.8|1.4|0.3|Singapore;SL|-11.8|8.6|0.5|Sierra Leone;SC|55.5|-4.7|0.3|Seychelles;RS|20.8|44.2|0.7|Serbia;SN|-14.8|15.1|0.9|Senegal;SA|44.7|23.8|3.0|Saudi Arabia;ST|7.0|1.0|0.3|Sao Tome and Principe;SM|12.4|43.9|0.3|San Marino;WS|-172.4|-13.6|0.3|Samoa;VC|-61.3|13.1|0.3|St. Vin. and Gren.;LC|-61.0|13.9|0.3|Saint Lucia;KN|-62.8|17.3|0.3|St. Kitts and Nevis;RW|30.1|-1.9|0.3|Rwanda;RU|44.7|58.2|3.0|Russia;RO|25.0|45.7|1.1|Romania;QA|51.1|25.2|0.3|Qatar;PT|-8.3|39.6|2.6|Portugal;PL|19.5|52.0|1.3|Poland;PH|122.5|11.2|2.1|Philippines;PE|-72.9|-13.0|2.5|Peru;PY|-60.1|-21.7|1.4|Paraguay;PG|143.9|-5.7|2.1|Papua New Guinea;PA|-80.4|8.7|0.6|Panama;PW|134.6|7.5|0.7|Palau;PK|68.5|29.3|2.4|Pakistan;OM|57.3|22.1|1.5|Oman;NO|9.7|61.4|3.0|Norway;KP|126.4|39.9|1.0|North Korea;NG|7.5|9.4|1.8|Nigeria;NE|9.5|17.4|2.3|Niger;NI|-85.1|12.7|0.7|Nicaragua;NZ|172.8|-39.8|3.0|New Zealand;NU|-169.9|-19.0|0.3|Niue;CK|-159.8|-21.2|0.3|Cook Is.;NL|5.6|52.4|3.0|Netherlands;AW|-70.0|12.5|0.3|Aruba;CW|-68.9|12.1|0.3|Curacao;NP|83.6|28.3|1.0|Nepal;NR|166.9|-0.5|0.3|Nauru;NA|17.1|-20.6|2.1|Namibia;MZ|37.8|-13.9|2.2|Mozambique;MA|-7.2|31.7|2.5|Morocco;EH|-12.6|24.0|1.3|W. Sahara;ME|19.1|42.8|0.3|Montenegro;MN|104.2|46.0|3.0|Mongolia;MD|28.5|47.4|0.5|Moldova;MC|7.4|43.7|0.3|Monaco;MX|-102.3|23.9|3.0|Mexico;MU|57.6|-20.3|0.3|Mauritius;MR|-9.7|19.6|2.1|Mauritania;MT|14.4|35.9|0.3|Malta;ML|-2.0|18.7|2.6|Mali;MV|73.5|4.2|0.3|Maldives;MY|113.8|2.5|1.9|Malaysia;MW|33.6|-13.4|0.8|Malawi;MG|46.7|-18.6|1.6|Madagascar;MK|21.6|41.6|0.3|North Macedonia;LU|6.1|49.7|0.3|Luxembourg;LT|24.1|55.1|0.6|Lithuania;LI|9.6|47.1|0.3|Liechtenstein;LY|18.0|26.6|2.5|Libya;LR|-9.5|6.4|0.7|Liberia;LS|28.2|-29.5|0.4|Lesotho;LB|36.0|34.1|0.3|Lebanon;LV|25.5|57.1|0.7|Latvia;LA|102.5|19.4|1.3|Laos;KG|74.5|41.7|1.1|Kyrgyzstan;KW|47.3|29.4|0.3|Kuwait;XK|20.9|42.6|0.3|Kosovo;KI|-157.4|1.8|3.0|Kiribati;KE|37.9|0.5|1.5|Kenya;KZ|68.7|49.1|3.0|Kazakhstan;JO|36.4|30.8|0.7|Jordan;JP|138.4|36.1|3.0|Japan;JM|-77.3|18.1|0.3|Jamaica;IT|11.1|44.7|1.9|Italy;IL|34.8|30.9|0.4|Israel;PS|35.3|32.0|0.3|Palestine;IE|-7.8|53.1|0.7|Ireland;IQ|43.3|33.1|1.5|Iraq;IR|54.9|32.2|2.8|Iran;ID|101.9|-1.0|3.0|Indonesia;IN|79.4|22.7|3.0|India;IS|-18.7|64.8|1.0|Iceland;HU|19.4|47.1|0.7|Hungary;HN|-86.9|14.8|0.8|Honduras;HT|-72.2|19.3|0.4|Haiti;GY|-58.9|5.1|1.0|Guyana;GW|-14.5|12.2|0.4|Guinea-Bissau;GN|-10.0|10.6|1.1|Guinea;GT|-90.5|15.0|0.7|Guatemala;GD|-61.7|12.1|0.3|Grenada;GR|21.7|39.5|1.3|Greece;GH|-1.0|7.7|0.9|Ghana;DE|9.7|51.0|1.4|Germany;GE|43.7|41.9|0.7|Georgia;GM|-15.0|13.6|0.3|Gambia;GA|11.8|-0.4|1.0|Gabon;FR|2.6|46.7|3.0|France;PM|-56.3|47.0|0.3|St. Pierre and Miquelon;WF|-178.1|-14.3|0.3|Wallis and Futuna Is.;MF|-63.0|18.1|0.3|St-Martin;BL|-62.8|17.9|0.3|St-Barthelemy;PF|-149.5|-17.6|2.3|Fr. Polynesia;NC|165.1|-21.1|0.9|New Caledonia;TF|69.1|-49.3|1.3|Fr. S. Antarctic Lands;AX|19.9|60.2|0.3|Aland;FI|27.3|63.3|1.8|Finland;FJ|178.0|-17.8|3.0|Fiji;ET|39.1|8.0|2.2|Ethiopia;EE|25.9|58.7|0.6|Estonia;ER|38.3|15.8|1.0|Eritrea;GQ|9.0|2.3|0.5|Eq. Guinea;SV|-88.9|13.7|0.3|El Salvador;EG|29.4|26.2|1.8|Egypt;EC|-78.2|-1.3|1.7|Ecuador;DO|-70.7|19.1|0.5|Dominican Rep.;DM|-61.3|15.5|0.3|Dominica;DJ|42.5|12.0|0.3|Djibouti;GL|-39.3|74.3|3.0|Greenland;FO|-7.1|62.2|0.3|Faeroe Is.;DK|9.0|56.0|0.8|Denmark;CZ|15.4|49.9|0.7|Czechia;CY|33.1|34.9|0.3|Cyprus;CU|-78.0|21.3|1.0|Cuba;HR|16.4|45.8|0.8|Croatia;CI|-5.6|7.5|1.0|Cote d'Ivoire;CR|-84.1|10.1|0.5|Costa Rica;CD|23.5|-1.9|3.0|Dem. Rep. Congo;CG|15.9|0.1|1.3|Congo;KM|43.3|-11.7|0.3|Comoros;CO|-73.2|3.4|2.4|Colombia;CN|106.3|32.5|3.0|China;MO|113.6|22.1|0.3|Macao;HK|114.1|22.4|0.3|Hong Kong;CL|-72.3|-38.2|3.0|Chile;TD|18.6|15.1|2.2|Chad;CF|20.9|7.0|1.8|Central African Rep.;CV|-23.6|15.1|0.4|Cabo Verde;CA|-101.9|60.3|3.0|Canada;CM|12.5|4.6|1.6|Cameroon;KH|104.5|12.6|0.8|Cambodia;MM|95.8|21.6|2.2|Myanmar;BI|29.9|-3.3|0.3|Burundi;BF|-1.4|12.7|1.1|Burkina Faso;BG|25.2|42.5|0.7|Bulgaria;BN|114.6|4.4|0.3|Brunei;BR|-49.6|-12.1|3.0|Brazil;BW|24.2|-22.1|1.5|Botswana;BA|18.1|44.1|0.5|Bosnia and Herz.;BO|-64.6|-16.7|2.1|Bolivia;BT|90.0|27.5|0.4|Bhutan;BJ|2.4|10.3|0.7|Benin;BZ|-88.7|17.2|0.3|Belize;BE|4.8|50.8|0.5|Belgium;BY|28.4|53.8|1.1|Belarus;BB|-59.6|13.2|0.3|Barbados;BD|89.7|24.2|0.9|Bangladesh;BH|50.6|26.1|0.3|Bahrain;BS|-77.1|26.4|1.0|Bahamas;AZ|47.2|40.4|0.7|Azerbaijan;AT|14.1|47.5|0.7|Austria;AU|134.0|-24.1|3.0|Australia;HM|73.5|-53.1|0.3|Heard I. and McDonald Is.;NF|168.0|-29.0|0.3|Norfolk Island;AM|44.8|40.5|0.5|Armenia;AR|-64.2|-33.5|3.0|Argentina;AG|-61.8|17.4|0.3|Antigua and Barb.;AO|18.0|-12.2|2.2|Angola;AD|1.5|42.5|0.3|Andorra;DZ|2.8|27.4|3.0|Algeria;AL|20.1|40.7|0.4|Albania;AF|66.5|34.2|1.9|Afghanistan;AQ|35.9|-79.8|3.0|Antarctica;SX|-63.1|18.0|0.3|Sint Maarten;TV|179.2|-8.5|0.3|Tuvalu" };
var tv = { open: false, full: false, poll: null, beat: null, raf: 0, clock: null, seq: -1, ts: 0, first: 0, home: "", homeip: "", homepos: null, skynet: 0, geomonth: "",
  started: 0, lastdata: 0, alerts: {}, samples: [], events: [], arcs: [], marks: {}, live: true, rtimers: [], tab: "feed", W: 0, H: 0, s: 1, ox: 0, oy: 0,
  dpr: 1, base: null, fx: null, land: null, coast: null, cc: {}, geo: null, geoload: 0, still: false, basetime: 0, tipcc: "" };
var tvcolors = { critical: [255, 95, 82], warning: [255, 193, 77], bg: [143, 180, 200] };
var tvkeep = 900, tvmaxarcs = 160;

function tvinitmap() {
  var b = atob(tvmap.mask), i, a, c, p;
  tv.land = [];
  for (i = 0; i < tvmap.cols * tvmap.rows; i++) if ((b.charCodeAt(i >> 3) >> (i & 7)) & 1) tv.land.push(i);
  tv.coast = [];
  a = tvmap.coast.split(" ");
  for (i = 0; i < a.length; i++) tv.coast.push(tvdecode(a[i]));
  a = tvmap.countries.split(";");
  for (i = 0; i < a.length; i++) { c = a[i].split("|"); if (c.length === 5) tv.cc[c[0]] = { lon: +c[1], lat: +c[2], r: +c[3], name: c[4] }; }
  p = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;
  tv.still = !!(p && p.matches);
}
function tvdecode(s) {
  var pts = [], i = 0, x = 0, y = 0, k, r, sh, b, v;
  while (i < s.length) {
    for (k = 0; k < 2; k++) {
      r = 0; sh = 0;
      do { b = s.charCodeAt(i++) - 63; r |= (b & 31) << sh; sh += 5; } while (b >= 32 && i < s.length);
      v = (r & 1) ? ~(r >> 1) : (r >> 1);
      if (k) y += v; else x += v;
    }
    pts.push([x / 10, y / 10]);
  }
  return pts;
}
function tvipnum(ip) {
  var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  return m ? ((+m[1]) * 16777216 + (+m[2]) * 65536 + (+m[3]) * 256 + (+m[4])) : -1;
}
function tvlookup(ip) {
  var g = tv.geo, n = tvipnum(ip), lo = 0, hi, mid;
  if (!g || n < 0) return "";
  hi = g.n - 1;
  while (lo < hi) { mid = (lo + hi + 1) >> 1; if (g.start[mid] <= n) lo = mid; else hi = mid - 1; }
  return g.start[lo] <= n ? g.code[lo] : "";
}
function tvloadgeo() {
  var x = new XMLHttpRequest();
  if (tv.geoload && Date.now() - tv.geoload < 300000) return;
  tv.geoload = Date.now();
  x.open("GET", datapath + "geoip.htm?m=" + encodeURIComponent(tv.geomonth || "x") + "l1", true);
  x.onreadystatechange = function () {
    if (x.readyState !== 4) return;
    var t = x.status === 200 ? x.responseText : "", lines, i, m, start = [], code = [], ok = t.substring(0, 8) === "iocmon=1";
    if (ok && t.substring(0, 300).indexOf("\nfmt=2\n") < 0) {
      tvnote("The country table on the router is from an older IOCMON. The monitor rebuilds it at its next cycle; reopen Threat View after that.");
      return;
    }
    if (ok) {
      lines = t.split("\n");
      for (i = 1; i < lines.length; i++) {
        m = /^([0-9a-f]{1,8})([A-Z]{2}|--)$/.exec(lines[i]);
        if (m) { start.push(parseInt(m[1], 16)); code.push(m[2] === "--" || m[2] === "ZZ" ? "" : m[2]); }
      }
    }
    if (start.length > 1000) {
      tv.geo = { start: new Float64Array(start), code: code, n: start.length };
      tvhome();
      tvnote("");
    } else {
      tvnote("Country table not ready yet: IOCMON downloads it once a month while a USB drive is in use. The feed works meanwhile; arcs appear once it is built.");
    }
  };
  x.send(null);
}
function tvnote(t) { var e = byid("tv_note"); e.textContent = t; e.style.display = t ? "block" : "none"; }
function tvmsg(t) { var e = byid("tv_msg"); e.textContent = t; e.style.display = t ? "block" : "none"; }

function tvhome() {
  var own = "", m, c;
  try { own = localStorage.getItem("iocmon_tvhome") || ""; } catch (e) { own = ""; }
  m = /^\s*(-?\d+(\.\d+)?)\s*,\s*(-?\d+(\.\d+)?)\s*$/.exec(own);
  if (m && Math.abs(+m[1]) <= 90 && Math.abs(+m[3]) <= 180) { tv.homepos = { lat: +m[1], lon: +m[3] }; put("tv_home", m[1] + ", " + m[3] + " (set in this browser)"); return; }
  c = tv.homeip ? tvlookup(tv.homeip) : "";
  if (c && tv.cc[c]) { tv.homepos = { lat: tv.cc[c].lat, lon: tv.cc[c].lon }; put("tv_home", tv.cc[c].name + " (from the WAN address)"); }
  else { tv.homepos = null; put("tv_home", tv.geo ? "unknown - set a location" : "waiting for the country table"); }
}
function tvsethome() {
  var cur = "", v;
  try { cur = localStorage.getItem("iocmon_tvhome") || ""; } catch (e) { cur = ""; }
  v = window.prompt("Home location as latitude, longitude (for example 43.65, -79.38). Leave empty to use the WAN address's country. Kept only in this browser.", cur);
  if (v === null) return;
  try { if (/\S/.test(v)) localStorage.setItem("iocmon_tvhome", v); else localStorage.removeItem("iocmon_tvhome"); } catch (e) { }
  tvhome();
}

function tvlayout() {
  var st = byid("tv_stage"), w, h, aspect = 360 / (tvmap.rows * tvmap.step), b = byid("tv_base"), f = byid("tv_fx");
  w = st.clientWidth;
  if (!tv.full) { h = Math.round(w / aspect) + 20; st.style.height = h + "px"; } else { st.style.height = ""; h = st.clientHeight; }
  if (w < 50 || h < 50) return;
  tv.dpr = window.devicePixelRatio || 1;
  tv.W = w; tv.H = h;
  tv.s = Math.min(w / 360, (h - 20) / (tvmap.rows * tvmap.step));
  tv.ox = (w - 360 * tv.s) / 2; tv.oy = (h - tvmap.rows * tvmap.step * tv.s) / 2 + 6;
  b.width = f.width = Math.round(w * tv.dpr); b.height = f.height = Math.round(h * tv.dpr);
  b.style.width = f.style.width = w + "px"; b.style.height = f.style.height = h + "px";
  tv.base = b.getContext("2d"); tv.fx = f.getContext("2d");
  tv.base.setTransform(tv.dpr, 0, 0, tv.dpr, 0, 0); tv.fx.setTransform(tv.dpr, 0, 0, tv.dpr, 0, 0);
  tvdrawbase();
}
function tvx(lon) { return tv.ox + (lon + 180) * tv.s; }
function tvy(lat) { return tv.oy + (tvmap.top - lat) * tv.s; }
function tvsun(t) {
  var n = t / 86400000 - 10957.5, rad = Math.PI / 180, L = (280.46 + 0.9856474 * n) % 360, g = (357.528 + 0.9856003 * n) * rad;
  var lam = (L + 1.915 * Math.sin(g) + 0.02 * Math.sin(2 * g)) * rad, eps = 23.439 * rad;
  var dec = Math.asin(Math.sin(eps) * Math.sin(lam)), ra = Math.atan2(Math.cos(eps) * Math.sin(lam), Math.cos(lam)) / rad;
  var gmst = (18.697374558 + 24.06570982441908 * n) % 24, lon = ((ra - gmst * 15) % 360 + 540) % 360 - 180;
  return { dec: dec, lon: lon };
}
function tvdrawbase() {
  var c = tv.base, sun = tvsun(Date.now()), rad = Math.PI / 180, i, k, col, row, lon, lat, cz, d = Math.max(0.7, tv.s * tvmap.step * 0.36), pts, j, lx;
  tv.basetime = Date.now();
  c.clearRect(0, 0, tv.W, tv.H);
  c.strokeStyle = "rgba(47,208,228,0.06)"; c.lineWidth = 1;
  c.beginPath();
  for (lon = -180; lon <= 180; lon += 30) { c.moveTo(tvx(lon), tvy(tvmap.top)); c.lineTo(tvx(lon), tvy(tvmap.top - tvmap.rows * tvmap.step)); }
  for (lat = 60; lat >= -50; lat -= 30) { c.moveTo(tvx(-180), tvy(lat)); c.lineTo(tvx(180), tvy(lat)); }
  c.stroke();
  for (k = 0; k < tv.land.length; k++) {
    i = tv.land[k]; col = i % tvmap.cols; row = (i - col) / tvmap.cols;
    lon = -180 + tvmap.step * (col + 0.5); lat = tvmap.top - tvmap.step * (row + 0.5);
    cz = Math.sin(lat * rad) * Math.sin(sun.dec) + Math.cos(lat * rad) * Math.cos(sun.dec) * Math.cos((lon - sun.lon) * rad);
    c.fillStyle = cz > 0 ? "rgba(47,208,228," + (0.42 + 0.3 * cz).toFixed(2) + ")" : "rgba(47,208,228,0.16)";
    c.beginPath(); c.arc(tvx(lon), tvy(lat), d, 0, 6.2832); c.fill();
  }
  c.save();
  c.strokeStyle = "rgba(120,235,250,0.38)"; c.lineWidth = 0.8; c.shadowColor = "rgba(47,208,228,0.9)"; c.shadowBlur = 6;
  c.beginPath();
  for (k = 0; k < tv.coast.length; k++) {
    pts = tv.coast[k]; lx = null;
    for (j = 0; j < pts.length; j++) {
      if (lx === null || Math.abs(pts[j][0] - lx) > 180) c.moveTo(tvx(pts[j][0]), tvy(pts[j][1])); else c.lineTo(tvx(pts[j][0]), tvy(pts[j][1]));
      lx = pts[j][0];
    }
  }
  c.stroke();
  c.restore();
  c.save();
  c.strokeStyle = "rgba(255,193,77,0.28)"; c.lineWidth = 1; c.setLineDash([2, 4]);
  c.beginPath();
  for (lon = -180; lon <= 180; lon += 2) {
    lat = Math.atan(-Math.cos((lon - sun.lon) * rad) / Math.tan(Math.abs(sun.dec) < 1e-4 ? 1e-4 : sun.dec)) / rad;
    lat = Math.max(Math.min(lat, tvmap.top), tvmap.top - tvmap.rows * tvmap.step);
    if (lon === -180) c.moveTo(tvx(lon), tvy(lat)); else c.lineTo(tvx(lon), tvy(lat));
  }
  c.stroke();
  c.restore();
}

function tvpos(cc, ip) {
  var c = tv.cc[cc], h = tvipnum(ip), a, r;
  if (!c) return null;
  if (h < 0) h = 0;
  a = ((h * 2654435761) % 3600) / 10 * Math.PI / 180; r = c.r * ((h >>> 3) % 97) / 97;
  return { lon: c.lon + r * Math.cos(a), lat: c.lat + r * Math.sin(a) * 0.7 };
}
function tvisdns(e) { return e.dir === "out" && (e.port === "53" || e.port === "853"); }
function tvshown(e) {
  if (e.sev === "bg" && tvisdns(e) && !byid("tf_dns").checked) return false;
  if (e.dir === "in" && !byid("tf_in").checked) return false;
  if (e.dir === "out" && !byid("tf_out").checked) return false;
  if (e.blocked && !byid("tf_blk").checked) return false;
  if (!e.blocked && !byid("tf_ok").checked) return false;
  if (byid("tf_flag").checked && e.sev === "bg") return false;
  return true;
}
function tvlaunch(e, when) {
  var p, x0, y0, x1, y1, h, dist, cx, cy, rgb = tvcolors[e.sev];
  if (!tv.homepos || !e.cc || !tvshown(e)) return;
  p = tvpos(e.cc, e.ip);
  if (!p) return;
  if (tv.arcs.length >= 600) tv.arcs.shift();
  h = { x: tvx(tv.homepos.lon), y: tvy(tv.homepos.lat) };
  if (e.dir === "out") { x0 = h.x; y0 = h.y; x1 = tvx(p.lon); y1 = tvy(p.lat); } else { x0 = tvx(p.lon); y0 = tvy(p.lat); x1 = h.x; y1 = h.y; }
  dist = Math.sqrt((x1 - x0) * (x1 - x0) + (y1 - y0) * (y1 - y0));
  cx = (x0 + x1) / 2; cy = Math.max(4, (y0 + y1) / 2 - Math.min(dist * 0.38, tv.H * 0.42));
  tv.arcs.push({ x0: x0, y0: y0, x1: x1, y1: y1, cx: cx, cy: cy, t0: when, dur: 1300 + dist / Math.max(tv.W, 1) * 2600, rgb: rgb,
                 w: e.sev === "critical" ? 2.6 : e.sev === "warning" ? 1.9 : 1.1, a: e.blocked ? 0.5 : 0.95, dash: e.blocked });
  tvmark(e, when);
}
function tvmark(e, when) {
  var m = tv.marks[e.cc];
  if (!m) m = tv.marks[e.cc] = { n: 0, last: 0, sev: "bg", ips: {} };
  m.n += e.count; m.last = Math.max(m.last, when);
  if (e.sev === "critical" || (e.sev === "warning" && m.sev === "bg")) m.sev = e.sev;
}
function tvbez(a, t) {
  var u = 1 - t;
  return { x: u * u * a.x0 + 2 * u * t * a.cx + t * t * a.x1, y: u * u * a.y0 + 2 * u * t * a.cy + t * t * a.y1 };
}
function tvrgba(rgb, a) { return "rgba(" + rgb[0] + "," + rgb[1] + "," + rgb[2] + "," + a.toFixed(3) + ")"; }
function tvframe() {
  var c = tv.fx, now = Date.now(), keep = [], i, a, p, ta, tb, k, q, g, h, cc, m, age, r, pos, al;
  tv.raf = 0;
  if (!tv.open || !c) return;
  if (now - tv.basetime > 60000) tvdrawbase();
  c.clearRect(0, 0, tv.W, tv.H);
  if (tv.homepos) {
    h = { x: tvx(tv.homepos.lon), y: tvy(tv.homepos.lat) };
    for (cc in tv.alerts) {
      al = tv.alerts[cc]; pos = tvpos(al.cc, al.ip);
      if (!pos) continue;
      a = { x0: h.x, y0: h.y, x1: tvx(pos.lon), y1: tvy(pos.lat) };
      k = Math.sqrt((a.x1 - a.x0) * (a.x1 - a.x0) + (a.y1 - a.y0) * (a.y1 - a.y0));
      a.cx = (a.x0 + a.x1) / 2; a.cy = Math.max(4, (a.y0 + a.y1) / 2 - Math.min(k * 0.38, tv.H * 0.42));
      q = tv.still ? 0.55 : 0.4 + 0.25 * Math.sin(now / 400);
      c.strokeStyle = tvrgba(tvcolors[al.sev], q); c.lineWidth = al.sev === "critical" ? 2.4 : 1.7; c.setLineDash([]);
      c.beginPath(); c.moveTo(a.x0, a.y0); c.quadraticCurveTo(a.cx, a.cy, a.x1, a.y1); c.stroke();
      c.fillStyle = tvrgba(tvcolors[al.sev], 0.9); c.beginPath(); c.arc(a.x1, a.y1, 3 + (tv.still ? 0 : 1.5 * Math.sin(now / 300)), 0, 6.2832); c.fill();
    }
  }
  for (cc in tv.marks) {
    m = tv.marks[cc]; age = now - m.last;
    if (age > 90000) { delete tv.marks[cc]; continue; }
    if (age < 0 || !tv.cc[cc]) continue;
    r = 1.5 + Math.min(5, Math.log(m.n + 1) / Math.LN2 * 0.8);
    c.fillStyle = tvrgba(tvcolors[m.sev], 0.75 * (1 - age / 90000));
    c.beginPath(); c.arc(tvx(tv.cc[cc].lon), tvy(tv.cc[cc].lat), r, 0, 6.2832); c.fill();
  }
  for (i = 0; i < tv.arcs.length; i++) {
    a = tv.arcs[i]; p = (now - a.t0) / a.dur;
    if (p < 0) { keep.push(a); continue; }
    if (p > 1.6) continue;
    keep.push(a);
    c.setLineDash(a.dash ? [4, 4] : []); c.lineWidth = a.w;
    if (tv.still) {
      c.strokeStyle = tvrgba(a.rgb, a.a * Math.max(0, 1 - p / 1.6));
      c.beginPath(); c.moveTo(a.x0, a.y0); c.quadraticCurveTo(a.cx, a.cy, a.x1, a.y1); c.stroke();
      continue;
    }
    tb = Math.min(1, p); ta = Math.max(0, tb - 0.35);
    if (p > 1) ta = Math.min(1, ta + (p - 1) * 0.7);
    if (tb > ta) {
      q = tvbez(a, ta); k = tvbez(a, tb);
      g = c.createLinearGradient(q.x, q.y, k.x, k.y);
      g.addColorStop(0, tvrgba(a.rgb, 0)); g.addColorStop(1, tvrgba(a.rgb, a.a));
      c.strokeStyle = g; c.beginPath(); c.moveTo(q.x, q.y);
      for (k = 1; k <= 14; k++) { q = tvbez(a, ta + (tb - ta) * k / 14); c.lineTo(q.x, q.y); }
      c.stroke();
    }
    c.setLineDash([]);
    if (p <= 1) {
      q = tvbez(a, p);
      c.fillStyle = tvrgba(a.rgb, a.a); c.shadowColor = tvrgba(a.rgb, 1); c.shadowBlur = 8;
      c.beginPath(); c.arc(q.x, q.y, a.w + 0.8, 0, 6.2832); c.fill(); c.shadowBlur = 0;
    } else {
      r = (p - 1) / 0.6; c.strokeStyle = tvrgba(a.rgb, a.a * (1 - r)); c.lineWidth = 1;
      c.beginPath(); c.arc(a.x1, a.y1, 2 + r * 10, 0, 6.2832); c.stroke();
    }
  }
  tv.arcs = keep;
  if (tv.homepos) {
    h = { x: tvx(tv.homepos.lon), y: tvy(tv.homepos.lat) }; r = tv.still ? 0 : (now % 2000) / 2000;
    c.fillStyle = "#bff6ff"; c.shadowColor = "#2fd0e4"; c.shadowBlur = 12;
    c.beginPath(); c.arc(h.x, h.y, 3.2, 0, 6.2832); c.fill(); c.shadowBlur = 0;
    c.strokeStyle = "rgba(47,208,228," + (0.7 * (1 - r)).toFixed(3) + ")"; c.lineWidth = 1.2;
    c.beginPath(); c.arc(h.x, h.y, 4 + r * 14, 0, 6.2832); c.stroke();
  }
  tv.raf = window.requestAnimationFrame(tvframe);
}

function tvparse(text) {
  var a = text.split("\n"), d = { ev: [], al: [], tot: null }, i, l, p, f;
  for (i = 1; i < a.length; i++) {
    l = unesc(a[i]);
    if (l.substring(0, 2) === "E|") {
      f = l.split("|");
      if (f.length >= 9) d.ev.push({ count: parseInt(f[1], 10) || 1, dir: f[2] === "out" ? "out" : "in", state: f[3], blocked: f[3] !== "allowed", ip: f[4],
                                     port: f[5], proto: f[6], dev: f[7], name: f.slice(8).join("|") });
    } else if (l.substring(0, 2) === "A|") {
      f = l.split("|"); if (f.length >= 4) d.al.push({ sev: f[1] === "critical" ? "critical" : "warning", kind: f[2], ip: f[3] });
    } else if (l.substring(0, 2) === "T|") {
      f = l.split("|"); d.tot = { out: +f[1] || 0, ain: +f[2] || 0, bin: +f[3] || 0, skin: +f[4] || 0, skout: +f[5] || 0, dns: +f[6] || 0 };
    } else if ((p = l.indexOf("=")) > 0) d[l.substring(0, p)] = l.substring(p + 1);
  }
  return d;
}
function tvpoll() {
  fetchdata("tv.htm", function (text) {
    var d, i, e, al, ts, bad = Date.now() - tv.started > 25000;
    if (!text) {
      if (!tv.lastdata) tvmsg(bad ? "No Threat View data from the router yet. Check that IOCMON is installed with its USB drive and that the web interface is on; the router starts sampling when this view is opened." : "Starting the Threat View sampler on the router...");
      else if (Date.now() - tv.lastdata > 30000) tvmsg("The router stopped sending samples. Trying again...");
      return;
    }
    d = tvparse(text);
    tv.lastdata = Date.now();
    tvmsg("");
    if (d.geo && d.geo !== tv.geomonth) { tv.geomonth = d.geo; if (!tv.geo) { tv.geoload = 0; tvloadgeo(); } }
    if (!tv.geo && !d.geo) tvnote("Country table not ready yet: IOCMON downloads it once a month while a USB drive is in use. The feed works meanwhile; arcs appear once it is built.");
    if (d.home !== tv.homeip) { tv.homeip = d.home || ""; tvhome(); }
    tv.skynet = d.skynet === "1";
    tv.alerts = {}; tv.alertips = {};
    for (i = 0; i < d.al.length; i++) {
      al = d.al[i]; al.cc = tvlookup(al.ip);
      if (!tv.alertips[al.ip] || al.sev === "critical") tv.alertips[al.ip] = al.sev;
      if (al.cc) tv.alerts[al.ip] = al;
    }
    tvdrawalert(d.al);
    if (d.seq === String(tv.seq)) { tvage(); return; }
    tv.seq = d.seq; tv.ts = parseInt(d.ts, 10) || Math.floor(Date.now() / 1000);
    ts = tv.ts;
    for (i = 0; i < d.ev.length; i++) {
      e = d.ev[i]; e.ts = ts; e.cc = tvlookup(e.ip);
      e.sev = tv.alertips[e.ip] || "bg";
    }
    tvorder(d.ev);
    tv.samples.push({ ts: ts, first: d.first === "1", ev: d.ev, tot: d.tot || { out: 0, ain: 0, bin: 0, skin: 0, skout: 0, dns: 0 },
                      sky: (parseInt(d.skyin, 10) || 0) + (parseInt(d.skyout, 10) || 0) });
    while (tv.samples.length && tv.samples[0].ts < ts - tvkeep) tv.samples.shift();
    if (tv.live) tvplay(d.ev, Date.now(), (parseInt(d.interval, 10) || 5) * 1000);
    tvaddfeed(d.ev);
    tvcounts();
    if (tv.tab === "top") tvdrawtop();
    if (tv.tab === "replay") tvrrange();
    tvage();
  });
}
function tvorder(ev) {
  var i, rank = function (e) { return (e.sev === "critical" ? 0 : e.sev === "warning" ? 1 : 2) * 8 + (e.dir === "in" ? 0 : tvisdns(e) ? 4 : 2) + (e.blocked ? 0 : 1); };
  for (i = 0; i < ev.length; i++) { ev[i].rk = rank(ev[i]); ev[i].ix = i; }
  ev.sort(function (a, b) { return a.rk - b.rk || b.count - a.count || a.ix - b.ix; });
}
function tvplay(ev, now, span) {
  var i, n = 0;
  for (i = 0; i < ev.length && n < tvmaxarcs; i++) {
    if (!ev[i].cc || !tvshown(ev[i])) continue;
    tvlaunch(ev[i], now + (ev.length > 1 ? Math.random() * span * 0.9 : 0));
    n++;
  }
}
function tvage() {
  var s = tv.lastdata ? Math.round((Date.now() - tv.lastdata) / 1000) : -1;
  put("tv_age", tv.ts ? tvtime(tv.ts) : "-");
  byid("tv_age").className = s > 20 ? "warn" : "";
}
function tvdrawalert(al) {
  var b = byid("tv_alert"), crit = 0, i;
  for (i = 0; i < al.length; i++) if (al[i].sev === "critical") crit++;
  if (!al.length) { b.style.display = "none"; return; }
  b.style.display = "flex";
  put("tv_alert_t", al.length + " unacknowledged alert address" + (al.length === 1 ? "" : "es") + " (" + crit + " critical) drawn in " + (crit ? "red" : "yellow") + " until acknowledged.");
}
function tvack() {
  put("tv_ack", "Acknowledging...");
  postaction("iocmonack");
  setTimeout(function () { put("tv_ack", "Acknowledge"); poll(); }, 6000);
}
function tvtime(ts) { var d = new Date(ts * 1000); return ("0" + d.getHours()).slice(-2) + ":" + ("0" + d.getMinutes()).slice(-2) + ":" + ("0" + d.getSeconds()).slice(-2); }
var tvresnote = {
  ALLOWED: "Allowed: the connection went through. Outbound, a device or the router opened it; inbound, the firewall let it in (a port forward, VPN server or router service).",
  FIREWALL: "Blocked by the router's own firewall: an unsolicited inbound attempt that was dropped. IOCMON records these on the WAN side.",
  SKYNET: "Blocked by Skynet: the address is on Skynet's blocklist, and Skynet dropped the packet before it reached the firewall (inbound or outbound)."
};
function tvrow(e) {
  var r = make("div", "tvrow" + (e.sev !== "bg" ? " " + e.sev : e.blocked ? " blk" : "")), dev = e.name || e.dev || "";
  r.appendChild(make("span", "num", tvtime(e.ts)));
  r.appendChild(make("span", "", e.dir === "out" ? "OUT" : "IN"));
  var res = e.state === "skynet" ? "SKYNET" : e.blocked ? "FIREWALL" : "ALLOWED", rs = make("span", "res", res);
  rs.title = tvresnote[res]; r.appendChild(rs);
  r.appendChild(make("span", "num", e.ip));
  r.appendChild(make("span", "", e.cc || "??"));
  r.appendChild(make("span", "num", (e.proto || "?") + (e.port ? "/" + e.port : "")));
  r.appendChild(make("span", "", dev));
  r.appendChild(make("span", "n num", e.count > 1 ? "x" + e.count : ""));
  r.title = (e.cc && tv.cc[e.cc] ? tv.cc[e.cc].name : "Unknown country") + (dev ? " | device " + dev : "");
  r.onclick = function () { tvtipfor(e.cc, null); };
  return r;
}
function tvaddfeed(ev) {
  var box = byid("tvp_feed"), i, n = 0, f = document.createDocumentFragment();
  for (i = ev.length - 1; i >= 0; i--) {
    tv.events.unshift(ev[i]);
  }
  if (tv.events.length > 400) tv.events.length = 400;
  if (tv.tab !== "feed") return;
  tvdrawfeed();
}
function tvfeedhead() {
  var r = make("div", "tvrow tvhead"), h = ["Time", "Dir", "Result", "Address", "CC", "Port", "Device", "Hits"], i, s;
  for (i = 0; i < h.length; i++) { s = make("span", i === 7 ? "n" : "", h[i]); if (i === 2) s.title = "ALLOWED: went through. FIREWALL: dropped by the router's firewall. SKYNET: dropped by Skynet's blocklist."; r.appendChild(s); }
  return r;
}
function tvdrawfeed() {
  var box = byid("tvp_feed"), i, n = 0, f = document.createDocumentFragment();
  for (i = 0; i < tv.events.length && n < 150; i++) if (tvshown(tv.events[i])) { f.appendChild(tvrow(tv.events[i])); n++; }
  clearnode(box);
  box.appendChild(tvfeedhead());
  if (!n) box.appendChild(make("div", "plain off", tv.lastdata ? "Nothing matching the filters yet." : "Waiting for the first sample..."));
  box.appendChild(f);
}
function tvcounts() {
  var now = tv.samples.length ? tv.samples[tv.samples.length - 1].ts : 0, i, j, s, c = { bin: 0, ain: 0, out: 0, dns: 0, bout: 0, sky: 0, flag: 0 }, span = 0, first = 0;
  for (i = tv.samples.length - 1; i >= 0; i--) {
    s = tv.samples[i];
    if (s.ts <= now - 60) break;
    if (s.first) continue;
    if (!first || s.ts < first) first = s.ts;
    c.bin += s.tot.bin + s.tot.skin; c.ain += s.tot.ain; c.out += s.tot.out - s.tot.dns; c.dns += s.tot.dns; c.bout += s.tot.skout; c.sky += s.sky;
    for (j = 0; j < s.ev.length; j++) if (s.ev[j].sev !== "bg") c.flag += s.ev[j].count;
  }
  span = first ? Math.max(5, now - first + 5) : 0;
  function rate(v) { return span ? String(Math.round(v * 60 / Math.min(60, span))) : "-"; }
  put("tc_bin", rate(c.bin)); put("tc_ain", rate(c.ain)); put("tc_out", rate(c.out)); put("tc_dns", rate(c.dns)); tvskytile("tc_bout", rate(c.bout)); tvskytile("tc_sky", rate(c.sky));
  byid("tvp_keysky").style.display = tv.samples.length && !tv.skynet ? "none" : ""; put("tc_flag", rate(c.flag));
  byid("tc_flag").className = c.flag ? "bad" : "";
}
function tvskytile(id, v) {
  var t = byid(id).parentNode.parentNode, off = tv.samples.length > 0 && !tv.skynet;
  if (!t.getAttribute("data-tip")) t.setAttribute("data-tip", t.title);
  t.className = off ? "off" : "";
  t.title = off ? "Skynet Firewall was not detected on this router, so there is nothing to count here. Everything else in Threat View works without it." : t.getAttribute("data-tip");
  put(id, off ? "Not installed" : tv.skynet ? v : "-");
}
function tvdrawtop() {
  var agg = { in: {}, out: {} }, i, j, e, d, k, list, box, max, r;
  for (i = 0; i < tv.samples.length; i++) for (j = 0; j < tv.samples[i].ev.length; j++) {
    e = tv.samples[i].ev[j];
    if (!tvshown(e)) continue;
    k = e.cc || "??"; agg[e.dir][k] = (agg[e.dir][k] || 0) + e.count;
  }
  for (d in agg) {
    list = []; for (k in agg[d]) list.push([k, agg[d][k]]);
    list.sort(function (a, b) { return b[1] - a[1]; });
    box = byid(d === "in" ? "tv_topin" : "tv_topout"); clearnode(box);
    max = list.length ? list[0][1] : 1;
    for (i = 0; i < list.length && i < 10; i++) {
      r = make("div", "tvbarrow");
      k = make("i"); k.style.width = Math.round(100 * list[i][1] / max) + "%"; r.appendChild(k);
      r.appendChild(make("span", "", (tv.cc[list[i][0]] ? tv.cc[list[i][0]].name : "Unknown") + " (" + list[i][0] + ")"));
      r.appendChild(make("span", "num", String(list[i][1])));
      r.style.cursor = "pointer";
      (function (c) { r.onclick = function () { tvtipfor(c, null); }; })(list[i][0]);
      box.appendChild(r);
    }
    if (!list.length) box.appendChild(make("div", "plain off", "None yet."));
  }
}
function tvtab(name) {
  var t = ["feed", "top", "replay"], i;
  tv.tab = name;
  for (i = 0; i < t.length; i++) { byid("tvt_" + t[i]).className = t[i] === name ? "sel" : ""; byid("tvp_" + t[i]).style.display = t[i] === name ? "" : "none"; }
  byid("tvp_key").style.display = name === "feed" ? "" : "none";
  if (name === "feed") tvdrawfeed(); else if (name === "top") tvdrawtop(); else tvrrange();
}
function tvfilter() { tvdrawfeed(); if (tv.tab === "top") tvdrawtop(); tvcounts(); }

function tvtipfor(cc, xy) {
  var tip = byid("tv_tip"), ips = {}, i, j, e, k, list = [], c = tv.cc[cc], box, row, l, x, y, t, tw, th;
  if (!cc) return;
  for (i = 0; i < tv.samples.length; i++) for (j = 0; j < tv.samples[i].ev.length; j++) {
    e = tv.samples[i].ev[j];
    if (e.cc !== cc) continue;
    k = ips[e.ip] || (ips[e.ip] = { ip: e.ip, n: 0, inb: 0, out: 0, blk: 0, ports: {}, sev: e.sev });
    k.n += e.count; if (e.dir === "in") k.inb += e.count; else k.out += e.count; if (e.blocked) k.blk += e.count;
    if (e.port) k.ports[e.proto + "/" + e.port] = 1;
  }
  for (k in tv.alerts) if (tv.alerts[k].cc === cc && !ips[k]) ips[k] = { ip: k, n: 0, inb: 0, out: 0, blk: 0, ports: {}, sev: tv.alerts[k].sev };
  for (k in ips) list.push(ips[k]);
  list.sort(function (a, b) { return (b.sev !== "bg") - (a.sev !== "bg") || b.n - a.n; });
  clearnode(tip);
  t = make("div", "tt"); t.appendChild(make("span", "", (c ? c.name : "Unknown country") + " (" + cc + ")"));
  l = make("a", "", "x"); l.onclick = function () { tip.style.display = "none"; tv.tipcc = ""; }; t.appendChild(l);
  tip.appendChild(t);
  tip.appendChild(make("div", "off", list.length + " address" + (list.length === 1 ? "" : "es") + " in the last 15 minutes"));
  for (i = 0; i < list.length && i < 12; i++) {
    e = list[i]; row = make("div", "ip");
    box = make("div", "num" + (e.sev === "critical" ? " bad" : e.sev === "warning" ? " warn" : ""), e.ip + "  in " + e.inb + " / out " + e.out + (e.blk ? " / blocked " + e.blk : ""));
    row.appendChild(box);
    k = []; for (j in e.ports) k.push(j);
    if (k.length) row.appendChild(make("div", "off", k.slice(0, 6).join(" ") + (k.length > 6 ? " ..." : "")));
    box = make("div", "links"); addlinks(box, e.ip); row.appendChild(box);
    tip.appendChild(row);
  }
  if (!xy && c) xy = { x: tvx(c.lon), y: tvy(c.lat) };
  tip.style.maxHeight = Math.max(80, Math.min(260, tv.H - 8)) + "px";
  tip.style.left = "0px"; tip.style.top = "0px"; tip.style.display = "block"; tip.scrollTop = 0;
  tw = tip.offsetWidth; th = tip.offsetHeight;
  x = xy ? Math.min(xy.x + 12, tv.W - tw - 4) : 8; y = xy ? Math.min(xy.y - 20, tv.H - th - 4) : 8;
  tip.style.left = Math.max(4, x) + "px"; tip.style.top = Math.max(4, y) + "px"; tv.tipcc = cc;
}
function tvclick(ev) {
  var r = byid("tv_fx").getBoundingClientRect(), x = ev.clientX - r.left, y = ev.clientY - r.top, best = "", bd = 144, cc, d, k, list = {};
  for (cc in tv.marks) list[cc] = 1;
  for (k in tv.alerts) list[tv.alerts[k].cc] = 1;
  for (cc in list) {
    if (!tv.cc[cc]) continue;
    d = Math.pow(tvx(tv.cc[cc].lon) - x, 2) + Math.pow(tvy(tv.cc[cc].lat) - y, 2);
    if (d < bd) { bd = d; best = cc; }
  }
  if (best) tvtipfor(best, { x: x, y: y }); else { byid("tv_tip").style.display = "none"; tv.tipcc = ""; }
}

function tvrrange() {
  var r = byid("tv_rpos"), n = tv.samples.length;
  r.max = Math.max(0, n - 1);
  if (tv.live) r.value = Math.max(0, n - 1);
  put("tv_rinfo", n ? n + " samples kept, " + tvtime(tv.samples[0].ts) + " to " + tvtime(tv.samples[n - 1].ts) + ". Pick a point and play it back." : "Samples are kept in this browser for 15 minutes while Threat View is open.");
  tvrlabel();
}
function tvrlabel() { var s = tv.samples[+byid("tv_rpos").value]; put("tv_rlabel", s ? tvtime(s.ts) + " (" + s.ev.length + " events)" : "-"); }
function tvreplay() {
  var start = +byid("tv_rpos").value, speed = +byid("tv_rspeed").value || 4, list = tv.samples.slice(start), t0, i, base = Date.now();
  if (!list.length) return;
  tvlive(true);
  tv.live = false;
  t0 = list[0].ts;
  for (i = 0; i < list.length; i++) (function (s, pos, delay) {
    tv.rtimers.push(setTimeout(function () {
      put("tv_rtag", "REPLAY " + tvtime(s.ts) + " (" + speed + "x)"); byid("tv_rtag").style.display = "block";
      if (tv.samples[pos] !== s) pos = tv.samples.indexOf(s);
      if (pos >= 0) { byid("tv_rpos").value = pos; tvrlabel(); }
      tvplay(s.ev, Date.now(), 5000 / speed);
    }, delay));
  })(list[i], start + i, (list[i].ts - t0) * 1000 / speed);
  tv.rtimers.push(setTimeout(function () { tvlive(); }, (list[list.length - 1].ts - t0) * 1000 / speed + 6000 / speed));
}
function tvlive(keep) {
  var i;
  for (i = 0; i < tv.rtimers.length; i++) clearTimeout(tv.rtimers[i]);
  tv.rtimers = []; tv.arcs = [];
  if (keep) return;
  tv.live = true; byid("tv_rtag").style.display = "none"; tvrrange();
}

function tvheartbeat() { if (tv.open && !document.hidden) postaction("iocmontv"); }
function tvclock() { var d = new Date(); put("tv_utc", ("0" + d.getUTCHours()).slice(-2) + ":" + ("0" + d.getUTCMinutes()).slice(-2) + ":" + ("0" + d.getUTCSeconds()).slice(-2)); }
function tvopen() {
  if (tv.open) return;
  if (!tv.land) { tvinitmap(); byid("tv_fx").onclick = tvclick; }
  tv.open = true; tv.started = Date.now();
  byid("dash").style.display = "none"; byid("tv").style.display = "";
  try { sessionStorage.setItem("iocmon_tv", "1"); } catch (e) { }
  tvlayout(); tvhome(); tvdrawfeed(); tvclock();
  if (!tv.lastdata) tvmsg("Starting the Threat View sampler on the router...");
  tvheartbeat(); tvloadgeo();
  tv.beat = setInterval(tvheartbeat, 30000);
  tv.poll = setInterval(tvpoll, 2000);
  tv.clock = setInterval(function () { tvclock(); tvage(); }, 1000);
  setTimeout(tvpoll, 700);
  if (!tv.raf) tv.raf = window.requestAnimationFrame(tvframe);
}
function tvclose() {
  if (tv.full) tvexpand();
  tv.open = false;
  clearInterval(tv.beat); clearInterval(tv.poll); clearInterval(tv.clock);
  if (tv.raf) window.cancelAnimationFrame(tv.raf);
  tv.raf = 0; tvlive();
  byid("tv").style.display = "none"; byid("dash").style.display = "";
  try { sessionStorage.removeItem("iocmon_tv"); } catch (e) { }
}
function tvexpand() {
  var el = byid("tv");
  if (tv.full && (document.fullscreenElement || document.webkitFullscreenElement)) { (document.exitFullscreen || document.webkitExitFullscreen).call(document); }
  tv.full = !tv.full;
  el.className = tv.full ? "tv full" + (tvdraweropen() ? " drawer" : "") : "tv";
  if (tv.full) byid("tv_stage").appendChild(byid("tv_panel")); else byid("tv_side").appendChild(byid("tv_panel"));
  tvdrawlabel();
  put("tv_exp", tv.full ? "Shrink" : "Expand");
  document.documentElement.style.overflow = tv.full ? "hidden" : "";
  tv.arcs = [];
  tvlayout();
}
function tvdraweropen() {
  try { return localStorage.getItem("iocmon_tvdrawer") === "1"; } catch (e) { return false; }
}
function tvdrawlabel() {
  var open = / drawer/.test(byid("tv").className);
  put("tv_drawbtn", open ? "◀ HIDE" : "▶ FEED");
  byid("tv_drawbtn").title = open ? "Hide the feed panel" : "Show the Live Feed, Top Countries and Replay panel";
}
function tvdrawer() {
  var el = byid("tv"), open = !/ drawer/.test(el.className);
  if (!tv.full) return;
  el.className = "tv full" + (open ? " drawer" : "");
  try { localStorage.setItem("iocmon_tvdrawer", open ? "1" : "0"); } catch (e) { }
  tvdrawlabel();
}
function tvfullscreen() {
  var el = byid("tv");
  if (document.fullscreenElement || document.webkitFullscreenElement) (document.exitFullscreen || document.webkitExitFullscreen).call(document);
  else if (el.requestFullscreen) el.requestFullscreen(); else if (el.webkitRequestFullscreen) el.webkitRequestFullscreen();
}
function tvinitpage() {
  window.addEventListener("resize", function () { if (tv.open) { tv.arcs = []; tvlayout(); } });
  document.addEventListener("fullscreenchange", function () { put("tv_fs", document.fullscreenElement ? "Exit Fullscreen" : "Fullscreen"); setTimeout(function () { if (tv.open) tvlayout(); }, 100); });
  document.addEventListener("visibilitychange", function () { if (!document.hidden) tvheartbeat(); });
  document.addEventListener("keydown", function (e) { if (e.key === "Escape" && tv.full && !document.fullscreenElement) tvexpand(); });
  try { if (sessionStorage.getItem("iocmon_tv") === "1") tvopen(); } catch (e) { }
}
(function () {
  function tvcalstr(b) { var s = atob(b), o = "", i; for (i = 0; i < s.length; i++) o += String.fromCharCode(s.charCodeAt(i) ^ (0x5a + i % 7)); return o.split("\n"); }
  function tvcalh(s) { var v = 5381, i; for (i = 0; i < s.length; i++) v = (v * 33 + s.charCodeAt(i)) % 4294967296; return v; }
  var S = tvcalstr("ExQfEBERQA4TDhgfC0AMEhkKfnJACB4REgoaQA4eDhAXESEWUR8SEBElGQ8VEhB/JQkPHR8SFjMSHhhXEhAnFRVmfRQQMxIOHVcXGyUUDxUJB38jFRUaFAwSJR51VhUbEywVd3wcGhIpFBIPCQweNBUJcldgfywTCAh9GR4tHwhWHAgeKRYaHhEbfycbFhkOZFVeegkJE34YLBUZHRF+CygIHh0JfgwpFw4QHAoWLxRRGxERHSEWewgVDBohDnsPFBMKLBsPFRIQVTMTFnweEhAjEXtWGRsZIxUVVgkXHE0OGh9wChAlUAgfGBAeMhMUD2d+VUB6e3x9CRYuFB4ODmR/UFAfDhwJVTMTFgkRHwspFRV8HhESMBYeCBhwVS4VewsUEBEpFBx8Dh0aLhsJFRJ+GS8PFRhzVA0lGRQREBsRJBsPFRIQZUARHhkNfgYvDwl8CRYNJRsPfBsbGiQJex8IDA0lFA9yVxsMI3oUDn0dEykZEHwJEX8lAhIIVxo2Eyo3PSR+KwUpL3J9Di0FKSh8GC08ASo+fDIsfwM2Mj82fisPejgwMi06TlALHR4VGjR6Dx0aVBkpCB4LHBITQBkTGQ4NVSIVDxIYCn8oDxUIVxoRM3oTFRkbfyEUH3wOGxorUAsTDwp/MxkaEn0cFi4dFFYHGw0vdx8dBH4PLxEeDlcdDS8UexYSHH8zFRcVCR8WMh9RFBwNF0AZFBARFwwpFRV8DxEKLB8PCBg=");
  var E = { on: false, buf: "", taps: [], timers: [], raf: 0, box: null, cv: null, cx: null, term: null, map: null, still: false,
    W: 0, H: 0, s: 1, ox: 0, oy: 0, fs: 13, phase: "", t0: 0, tracks: [], lv: 5, flash: 0, frozen: 0, boards: [], stage: 0, scen: 0, fade: 0, last: 0 };
  var L = [S[20], S[21], S[22], S[23], S[24], S[25],
    S[26], S[27], S[11], S[8]];
  var sites = ["US", "CA", "MX", "BR", "AR", "GB", "FR", "DE", "TR", "RU", "EG", "ZA", "IN", "CN", "KR", "JP", "AU"];
  var lines3 = [[0, 1, 2], [3, 4, 5], [6, 7, 8], [0, 3, 6], [1, 4, 7], [2, 5, 8], [0, 4, 8], [2, 4, 6]];
  var green = "57,255,106";
  var Q = [{ n: 1, step: 260, dur: 3300 }, { n: 8, step: 85, dur: 2500 }, { n: 18, step: 35, dur: 2600 }];

  function tvcalsafe(f) { return function () { try { return f.apply(this, arguments); } catch (e) { tvcalend(); } }; }
  function tvcalat(ms, f) { E.timers.push(setTimeout(tvcalsafe(f), ms)); }
  function tvcalnow() { return Date.now(); }
  function tvcalx(lon) { return E.ox + (lon + 180) * E.s; }
  function tvcaly(lat) { return E.oy + (tvmap.top - lat) * E.s; }
  function tvcalrgba(rgb, a) { return "rgba(" + rgb + "," + Math.max(0, Math.min(1, a)).toFixed(3) + ")"; }

  function tvcalstart() {
    var st;
    if (E.on || typeof tv === "undefined" || !tv.open || !tv.coast) return;
    st = document.getElementById("tv_stage");
    if (!st) return;
    E.on = true; E.still = !!tv.still; E.buf = ""; E.taps = []; E.tracks = []; E.boards = []; E.scen = 0; E.lv = 5; E.frozen = 0; E.fade = 0;
    E.box = document.createElement("div"); E.box.className = "tvcal";
    E.box.setAttribute("role", "dialog"); E.box.setAttribute("aria-label", S[19]);
    E.cv = document.createElement("canvas"); E.box.appendChild(E.cv);
    E.term = document.createElement("div"); E.term.className = "tvcalterm"; E.box.appendChild(E.term);
    E.hint = document.createElement("div"); E.hint.className = "tvcalhint"; E.hint.textContent = S[18]; E.box.appendChild(E.hint);
    E.box.addEventListener("click", function (ev) { ev.stopPropagation(); tvcalend(); });
    st.appendChild(E.box);
    E.W = E.H = 0; tvcalsize();
    E.phase = "p1"; E.t0 = tvcalnow();
    tvcalat(90000, tvcalend);
    tvcalintro();
    E.raf = window.requestAnimationFrame(tvcalsafe(tvcalframe));
  }

  function tvcalend() {
    var i;
    try {
      for (i = 0; i < E.timers.length; i++) clearTimeout(E.timers[i]);
      if (E.raf) window.cancelAnimationFrame(E.raf);
      if (E.box && E.box.parentNode) E.box.parentNode.removeChild(E.box);
    } catch (e) { }
    E.timers = []; E.raf = 0; E.box = E.cv = E.cx = E.term = E.map = null; E.on = false; E.phase = ""; E.tracks = []; E.boards = [];
  }

  function tvcalsize() {
    var st = E.box.parentNode, w = st.clientWidth, h = st.clientHeight, d = window.devicePixelRatio || 1;
    if (w === E.W && h === E.H) return;
    E.W = w; E.H = h;
    E.cv.width = Math.round(w * d); E.cv.height = Math.round(h * d); E.cv.style.width = w + "px"; E.cv.style.height = h + "px";
    E.cx = E.cv.getContext("2d"); E.cx.setTransform(d, 0, 0, d, 0, 0);
    E.s = Math.min(w / 360, (h - 24) / (tvmap.rows * tvmap.step));
    E.ox = (w - 360 * E.s) / 2; E.oy = (h - tvmap.rows * tvmap.step * E.s) / 2 + 8;
    E.fs = Math.max(10, Math.min(18, Math.floor(h / 19)));
    E.term.style.fontSize = E.fs + "px";
    E.map = null; E.tracks = [];
  }

  function tvcallines(list, done) {
    var i = 0, el;
    E.term.textContent = "";
    function next() {
      var row, txt, k = 0;
      if (i >= list.length) { if (done) done(); return; }
      txt = list[i++];
      row = document.createElement("div"); row.className = "tvcalrow"; E.term.appendChild(row);
      if (el) el.className = "tvcalrow";
      el = row;
      if (E.still || txt === "") { row.textContent = txt; tvcalat(E.still ? 260 : 120, next); return; }
      row.className = "tvcalrow cur";
      (function tvcaltyperow() {
        row.textContent = txt.slice(0, ++k);
        if (k < txt.length) tvcalat(txt.charAt(k - 1) === " " ? 55 : 32, tvcaltyperow); else tvcalat(320, next);
      })();
    }
    next();
  }

  function tvcalintro() {
    tvcallines([S[0], S[1], "", S[2], S[3], "",
      S[4], "", S[5]], function () { tvcalat(500, tvcalseq); });
  }

  function tvcalseq() {
    var rows = [], i, r, pick = 0;
    E.term.textContent = "";
    r = document.createElement("div"); r.className = "tvcalrow"; r.textContent = S[6]; E.term.appendChild(r);
    r = document.createElement("div"); r.className = "tvcalrow"; r.textContent = ""; E.term.appendChild(r);
    for (i = 0; i < L.length; i++) {
      r = document.createElement("div"); r.className = "tvcalrow";
      r.textContent = (i < 9 ? " " : "") + (i + 1) + ".  ";
      r.appendChild(document.createElement("span")).textContent = L[i];
      r.style.visibility = "hidden"; E.term.appendChild(r); rows.push(r);
    }
    function reveal() {
      if (pick < rows.length) { rows[pick++].style.visibility = ""; tvcalat(E.still ? 60 : 110, reveal); return; }
      pick = E.still ? rows.length - 1 : 0; step();
    }
    function step() {
      var j;
      for (j = 0; j < rows.length; j++) rows[j].firstElementChild.className = j === pick ? "inv" : "";
      if (pick < rows.length - 1) { pick++; tvcalat(230, step); return; }
      tvcalat(E.still ? 900 : 1100, function () {
        r = document.createElement("div"); r.className = "tvcalrow"; E.term.appendChild(r);
        r = document.createElement("div"); r.className = "tvcalrow"; E.term.appendChild(r);
        if (E.still) { r.textContent = S[7]; tvcalat(1200, tvcalrun); return; }
        var t = S[7], k = 0;
        r.className = "tvcalrow cur";
        (function tvcaltypecmd() { r.textContent = t.slice(0, ++k); if (k < t.length) tvcalat(34, tvcaltypecmd); else tvcalat(900, tvcalrun); })();
      });
    }
    reveal();
  }

  function tvcalrun() {
    var i;
    E.term.textContent = ""; E.phase = "p2"; E.t0 = tvcalnow(); E.spawned = 0; E.lv = 5; E.flash = E.t0;
    for (i = 1; i <= 4; i++) (function (d) { tvcalat(i * 2200, function () { E.lv = d; E.flash = tvcalnow(); }); })(5 - i);
    if (E.still) for (i = 0; i < 26; i++) tvcalspawn(E.t0 - 5000);
    tvcalat(10600, function () { E.frozen = tvcalnow(); });
    tvcalat(11800, tvcalgrid);
  }

  function tvcalsite() {
    var c = tv.cc[sites[Math.floor(Math.random() * sites.length)]];
    return c ? { x: tvcalx(c.lon + (Math.random() - 0.5) * c.r * 2), y: tvcaly(c.lat + (Math.random() - 0.5) * c.r) } : null;
  }
  function tvcalspawn(t) {
    var a = tvcalsite(), b = tvcalsite(), k;
    if (!a || !b || Math.abs(a.x - b.x) + Math.abs(a.y - b.y) < 30) return;
    k = Math.sqrt((a.x - b.x) * (a.x - b.x) + (a.y - b.y) * (a.y - b.y));
    E.tracks.push({ a: a, b: b, c: { x: (a.x + b.x) / 2, y: Math.max(6, (a.y + b.y) / 2 - Math.min(k * 0.45, E.H * 0.45)) }, t0: t,
      dur: 1500 + Math.random() * 1200, col: Math.random() < 0.5 ? "255,82,82" : "79,195,255" });
  }
  function tvcalpt(tr, p) { var q = 1 - p; return { x: q * q * tr.a.x + 2 * q * p * tr.c.x + p * p * tr.b.x, y: q * q * tr.a.y + 2 * q * p * tr.c.y + p * p * tr.b.y }; }

  function tvcalmapcache() {
    var c, k, j, pts, lx, d = window.devicePixelRatio || 1, lon, lat;
    E.map = document.createElement("canvas"); E.map.width = Math.round(E.W * d); E.map.height = Math.round(E.H * d);
    c = E.map.getContext("2d"); c.setTransform(d, 0, 0, d, 0, 0);
    c.strokeStyle = tvcalrgba(green, 0.07); c.lineWidth = 1; c.beginPath();
    for (lon = -180; lon <= 180; lon += 30) { c.moveTo(tvcalx(lon), tvcaly(tvmap.top)); c.lineTo(tvcalx(lon), tvcaly(tvmap.top - tvmap.rows * tvmap.step)); }
    for (lat = 60; lat >= -50; lat -= 30) { c.moveTo(tvcalx(-180), tvcaly(lat)); c.lineTo(tvcalx(180), tvcaly(lat)); }
    c.stroke();
    c.strokeStyle = tvcalrgba(green, 0.6); c.lineWidth = 1; c.shadowColor = tvcalrgba(green, 0.9); c.shadowBlur = 5; c.beginPath();
    for (k = 0; k < tv.coast.length; k++) {
      pts = tv.coast[k]; lx = null;
      for (j = 0; j < pts.length; j++) {
        if (lx === null || Math.abs(pts[j][0] - lx) > 180) c.moveTo(tvcalx(pts[j][0]), tvcaly(pts[j][1])); else c.lineTo(tvcalx(pts[j][0]), tvcaly(pts[j][1]));
        lx = pts[j][0];
      }
    }
    c.stroke();
  }

  function tvcalpaintrun(now, alpha, hud) {
    var c = E.cx, keep = [], i, tr, p, j, q, r, e = (now - E.t0) / 1000, n, rate, cw, x0, lit;
    if (!E.frozen && !E.still && E.phase === "p2") {
      n = Math.floor(1.2 * e + 0.95 * e * e);
      while (E.spawned < n) { E.spawned++; if (E.tracks.length < 150) tvcalspawn(now - Math.random() * 300); }
    }
    c.save(); c.globalAlpha = alpha; c.lineCap = "round";
    for (i = 0; i < E.tracks.length; i++) {
      tr = E.tracks[i]; p = Math.min(1, (now - tr.t0) / tr.dur);
      c.strokeStyle = tvcalrgba(tr.col, 0.85); c.lineWidth = 1.3; c.beginPath(); c.moveTo(tr.a.x, tr.a.y);
      for (j = 1; j <= 18; j++) { q = tvcalpt(tr, p * j / 18); c.lineTo(q.x, q.y); }
      c.stroke();
      if (p < 1) { q = tvcalpt(tr, p); c.fillStyle = "rgba(255,255,255,0.95)"; c.beginPath(); c.arc(q.x, q.y, 1.8, 0, 6.2832); c.fill(); keep.push(tr); continue; }
      r = (now - tr.t0 - tr.dur) / 700;
      if (E.still) { keep.push(tr); continue; }
      if (r < 1) { c.strokeStyle = tvcalrgba(tr.col, 1 - r); c.lineWidth = 1.5; c.beginPath(); c.arc(tr.b.x, tr.b.y, 2 + r * 11, 0, 6.2832); c.stroke(); keep.push(tr); }
    }
    if (!E.frozen) E.tracks = keep;
    if (!hud) { c.restore(); return; }
    c.font = "bold " + E.fs + "px 'Courier New', Courier, monospace"; c.textBaseline = "top";
    c.fillStyle = tvcalrgba(green, 0.95);
    c.fillText(S[8], 10, 8);
    c.fillText(S[9] + tvcalclock(E.frozen ? E.frozen - E.t0 : now - E.t0), 10, 10 + E.fs * 1.3);
    cw = Math.round(E.fs * 1.7); x0 = E.W - 10 - cw * 5 - 4 * 4;
    c.fillText(S[10], x0, 8);
    for (i = 0; i < 5; i++) {
      n = 5 - i; lit = n === E.lv && (E.still || (now - E.flash) > 900 || Math.floor((now - E.flash) / 150) % 2 === 0);
      c.strokeStyle = tvcalrgba(n === 1 ? "255,82,82" : green, 0.9); c.lineWidth = 1;
      c.strokeRect(x0 + i * (cw + 4) + 0.5, 10 + E.fs * 1.3 + 0.5, cw, cw);
      if (lit) { c.fillStyle = tvcalrgba(E.lv === 1 ? "255,82,82" : green, 0.9); c.fillRect(x0 + i * (cw + 4) + 2, 12 + E.fs * 1.3, cw - 3, cw - 3); }
      c.fillStyle = lit ? "#011a07" : tvcalrgba(green, 0.9);
      c.fillText(String(n), x0 + i * (cw + 4) + cw / 2 - E.fs * 0.3, 10 + E.fs * 1.3 + (cw - E.fs) / 2);
    }
    c.restore();
  }
  function tvcalclock(ms) {
    var s = Math.floor(ms * 0.36), z = function (v) { return ("0" + v).slice(-2); };
    return z(Math.floor(s / 3600) % 100) + ":" + z(Math.floor(s / 60) % 60) + ":" + z(s % 60);
  }

  function tvcalperm() {
    var tries, m, i, j, b, ok, t, l;
    for (tries = 0; tries < 400; tries++) {
      m = [0, 1, 2, 3, 4, 5, 6, 7, 8];
      for (i = 8; i > 0; i--) { j = Math.floor(Math.random() * (i + 1)); t = m[i]; m[i] = m[j]; m[j] = t; }
      b = []; ok = true;
      for (i = 0; i < 9 && ok; i++) {
        b[m[i]] = i % 2 ? "O" : "X";
        for (l = 0; l < 8; l++) if (b[lines3[l][0]] && b[lines3[l][0]] === b[lines3[l][1]] && b[lines3[l][1]] === b[lines3[l][2]]) ok = false;
      }
      if (ok) return m;
    }
    return [0, 4, 8, 2, 6, 3, 5, 7, 1];
  }
  function tvcalgrid() {
    E.phase = "p3"; E.fade = tvcalnow(); E.stage = 0; tvcalstage();
  }
  function tvcalstage() {
    var st = Q[E.stage], i, now = tvcalnow();
    E.boards = [];
    for (i = 0; i < st.n; i++) E.boards.push({ m: tvcalperm(), k: E.still ? 9 : 0, next: now + i * 23, done: E.still ? now : 0 });
    if (E.still) E.scen += st.n;
    tvcalat(st.dur, function () { E.stage++; if (E.stage < Q.length) tvcalstage(); else tvcaloutro(); });
  }
  function tvcalpaintgrid(now) {
    var c = E.cx, st = Q[E.stage] || Q[Q.length - 1], n = E.boards.length, cols, rows, top = E.fs * 3.2, aw = E.W * 0.92, ah = E.H - top - E.fs * 1.8, sz, i, b, bx, by, cs, k, cell, cx, cy, t;
    cols = Math.max(1, Math.min(n, Math.round(Math.sqrt(n * aw / ah)))); rows = Math.ceil(n / cols);
    sz = Math.min(aw / cols, ah / rows) * 0.78; cs = sz / 3;
    c.save(); c.lineCap = "round";
    c.font = "bold " + E.fs + "px 'Courier New', Courier, monospace"; c.textBaseline = "top"; c.fillStyle = tvcalrgba(green, 0.95);
    c.fillText(S[11], 10, 8);
    t = S[12] + E.scen + S[13]; c.fillText(t, E.W - 10 - c.measureText(t).width, 8);
    for (i = 0; i < n; i++) {
      b = E.boards[i];
      while (!E.still && b.k < 9 && now >= b.next) { b.k++; b.next += st.step; if (b.k === 9) { b.done = now; E.scen++; } }
      if (!E.still && b.done && now - b.done > Math.max(450, st.step * 6)) { b.m = tvcalperm(); b.k = 0; b.done = 0; b.next = now; }
      bx = (E.W - cols * (aw / cols)) / 2 + (i % cols) * (aw / cols) + (aw / cols - sz) / 2;
      by = top + Math.floor(i / cols) * (ah / rows) + (ah / rows - sz) / 2;
      c.strokeStyle = tvcalrgba(green, 0.75); c.lineWidth = Math.max(1, sz / 60); c.beginPath();
      for (k = 1; k < 3; k++) { c.moveTo(bx + k * cs, by + 3); c.lineTo(bx + k * cs, by + sz - 3); c.moveTo(bx + 3, by + k * cs); c.lineTo(bx + sz - 3, by + k * cs); }
      c.stroke();
      c.lineWidth = Math.max(1.2, sz / 40);
      for (k = 0; k < b.k; k++) {
        cell = b.m[k]; cx = bx + (cell % 3 + 0.5) * cs; cy = by + (Math.floor(cell / 3) + 0.5) * cs;
        c.strokeStyle = k % 2 ? tvcalrgba("79,195,255", 0.95) : tvcalrgba(green, 0.95); c.beginPath();
        if (k % 2) c.arc(cx, cy, cs * 0.3, 0, 6.2832); else { c.moveTo(cx - cs * 0.28, cy - cs * 0.28); c.lineTo(cx + cs * 0.28, cy + cs * 0.28); c.moveTo(cx + cs * 0.28, cy - cs * 0.28); c.lineTo(cx - cs * 0.28, cy + cs * 0.28); }
        c.stroke();
      }
      if (b.k === 9 && sz > 44) { c.fillStyle = tvcalrgba(green, 0.9); c.font = Math.max(9, Math.round(sz / 7)) + "px 'Courier New', Courier, monospace"; t = S[14]; c.fillText(t, bx + sz / 2 - c.measureText(t).width / 2, by + sz + 2); c.font = "bold " + E.fs + "px 'Courier New', Courier, monospace"; }
    }
    c.restore();
  }

  function tvcaloutro() {
    E.phase = "p4"; E.boards = []; E.tracks = [];
    tvcallines([S[15], S[16], "", S[17]], function () {
      tvcalat(3200, function () {
        if (!E.box) return;
        E.box.className = "tvcal out";
        tvcalat(E.still ? 0 : 900, tvcalend);
      });
    });
  }

  function tvcalframe() {
    var c, now = tvcalnow(), a;
    E.raf = 0;
    if (!E.on) return;
    if (typeof tv === "undefined" || !tv.open || !E.box || !E.box.parentNode || !E.box.parentNode.clientWidth) { tvcalend(); return; }
    tvcalsize();
    c = E.cx; c.clearRect(0, 0, E.W, E.H);
    if (E.phase === "p2" || E.phase === "p3") {
      if (!E.map) tvcalmapcache();
      a = E.phase === "p3" ? Math.max(0.15, 1 - (now - E.fade) / 2000) : 1;
      c.globalAlpha = a; c.drawImage(E.map, 0, 0, E.W, E.H); c.globalAlpha = 1;
      if (E.phase === "p2" || a > 0.16) tvcalpaintrun(E.frozen && E.phase === "p2" ? E.frozen : now, E.phase === "p3" ? a - 0.15 : 1, E.phase === "p2");
      if (E.phase === "p3") { c.fillStyle = "rgba(1,6,3," + Math.min(0.55, (now - E.fade) / 2000).toFixed(2) + ")"; c.fillRect(0, 0, E.W, E.H); tvcalpaintgrid(now); }
    }
    E.last = now;
    E.raf = window.requestAnimationFrame(tvcalsafe(tvcalframe));
  }

  function tvcalkey(e) {
    var t, k;
    if (E.on) {
      if (e.key === "Escape" || e.key === "Esc") { e.stopPropagation(); e.preventDefault(); tvcalend(); }
      return;
    }
    if (typeof tv === "undefined" || !tv.open || e.ctrlKey || e.metaKey || e.altKey) return;
    t = e.target || {};
    if (/^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName || "") || t.isContentEditable) return;
    k = e.key || "";
    if (!/^[a-z]$/i.test(k)) { E.buf = ""; return; }
    E.buf = (E.buf + k.toLowerCase()).slice(-6);
    if (tvcalh(E.buf) === 121327823) { E.buf = ""; tvcalstart(); }
  }
  function tvcaltap(e) {
    var r, x, y, now = tvcalnow(), i, keep = [];
    if (E.on || !e.target || e.target.id !== "tv_fx" || typeof tv === "undefined" || !tv.open || !tv.homepos) return;
    r = e.target.getBoundingClientRect(); x = e.clientX - r.left; y = e.clientY - r.top;
    if (Math.pow(x - tvx(tv.homepos.lon), 2) + Math.pow(y - tvy(tv.homepos.lat), 2) > 18 * 18) { E.taps = []; return; }
    for (i = 0; i < E.taps.length; i++) if (now - E.taps[i] < 3000) keep.push(E.taps[i]);
    keep.push(now); E.taps = keep;
    if (E.taps.length >= 5) { E.taps = []; tvcalstart(); }
  }
  try {
    window.addEventListener("keydown", tvcalsafe(tvcalkey), true);
    document.addEventListener("click", tvcalsafe(tvcaltap), true);
  } catch (e) { }
})();
function initial() {
  try { excopen = localStorage.getItem("iocmon_excshow") === "1"; } catch (e) { }
  excshowapply();
  try { show_menu(); } catch (e) { if (window.console) console.error("IOCMON: show_menu failed", e); }
  document.form.current_page.value = window.location.pathname.substring(1);
  put("f_ver", pagever);
  lastchange = Date.now();
  poll();
  postaction("iocmonautocheck");
  setInterval(poll, 15000);
  tvinitpage();
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
<div id="dash">

<div class="hdr" id="hdr">
  <div class="dot"></div>
  <div><div class="state" id="h_state">LOADING</div><div class="sub" id="h_sub">Reading IOCMON status...</div></div>
  <div class="right"><b>IOCMON <span id="h_ver"></span></b><br/><span id="h_router"></span><br/><span id="h_uptime"></span><br/><span class="auth" id="h_auth"></span></div>
</div>
<div class="banner red" id="b_auth" style="display:none"><div id="b_auth_x"><b id="b_auth_h"></b><span id="b_auth_t"></span></div><a class="btn ack" id="a_authack" onclick="acknowledge();" style="display:none">Acknowledge</a></div>
<div class="banner red" id="b_alert" style="display:none"><span id="b_alert_t"></span><a class="btn ack" id="a_ack" onclick="acknowledge();">Acknowledge</a></div>
<div class="banner amber" id="b_update" style="display:none"><span id="b_update_t"></span><a class="btn ack" onclick="installupdate();">Install Update</a></div>
<div class="banner amber" id="b_page" style="display:none"></div>

<div class="actions" id="actions">
  <a class="btn tvbtn" onclick="tvopen();">Threat View</a>
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
  <div class="cleartools"><a class="btn dis" id="l_clear" onclick="clearlog();">Clear Log</a></div>
  <div class="pager"><a id="l_prev" onclick="turn(-1);">&lt; Prev</a><span><span id="l_page"></span> | <span id="l_count"></span></span><a id="l_next" onclick="if(this.className!=='dis')turn(1);">Next &gt;</a></div>
</div>

<div class="panel"><h2 class="split">Exceptions<span class="fcols num"><span id="x_total"></span><a class="xshow" id="x_show" onclick="toggleexcpanel();">Show</a></span></h2>
<div id="x_body" style="display:none">
  <div class="tabs">
    <a id="xtab_dns" class="sel" onclick="pickexc('dns');"></a>
    <a id="xtab_ip" onclick="pickexc('ip');"></a>
    <a id="xtab_file" onclick="pickexc('file');"></a>
    <a id="xtab_cron" onclick="pickexc('cron');"></a>
  </div>
  <div class="plain off">Items in these lists never alert. Turn a switch off to remove an item from its list. Add items with the Exception switch at the right of an IoC Detections row, or in IOCMON's Advanced Settings.</div>
  <div id="x_lists"></div>
</div>
</div>
</div>

<div class="tv" id="tv" style="display:none">
  <div class="tvbar">
    <a class="btn" onclick="tvclose();">&lt; Back to Dashboard</a>
    <span class="tvtitle">THREAT VIEW</span>
    <span class="tvclock num"><b id="tv_utc"></b> UTC | sample <b id="tv_age">-</b></span>
    <a class="btn fsonly" id="tv_fs" onclick="tvfullscreen();">Fullscreen</a>
    <a class="btn" id="tv_exp" onclick="tvexpand();">Expand</a>
  </div>
  <div class="tvstage" id="tv_stage">
    <canvas id="tv_base"></canvas><canvas id="tv_fx"></canvas>
    <div class="tvmsg" id="tv_msg"></div>
    <div class="tvnote" id="tv_note"></div>
    <div class="tvreplaytag" id="tv_rtag"></div>
    <div class="tvlegend"><span><i style="color:#ff5f52;border-top-width:3px"></i>critical</span><span><i style="color:#ffc14d"></i>warning</span><span><i style="color:#8fb4c8"></i>traffic</span><span><i style="color:#8fb4c8;border-top-style:dashed;opacity:.6"></i>blocked</span></div>
    <div class="tvtip" id="tv_tip"></div>
  </div>
  <div class="tvside" id="tv_side">
  <div class="tvcounts">
    <div title="Inbound attempts dropped per minute: the router's firewall (unsolicited packets from the internet) plus Skynet's inbound blocklist drops it logged"><div class="k">Blocked in</div><div class="v num"><span id="tc_bin">-</span><small>/min</small></div></div>
    <div title="New connections started from the internet that the firewall let in: port forwards, UPnP, a VPN server or router services. Replies to connections your own devices opened are not counted, so this is usually 0-2 on a home network."><div class="k">Allowed in</div><div class="v num"><span id="tc_ain">-</span><small>/min</small></div></div>
    <div title="New connections your devices or the router opened to the internet, not counting DNS lookups"><div class="k">Outbound</div><div class="v num"><span id="tc_out">-</span><small>/min</small></div></div>
    <div title="DNS lookups to outside servers (port 53 and 853), counted separately from Outbound"><div class="k">DNS lookups</div><div class="v num"><span id="tc_dns">-</span><small>/min</small></div></div>
    <div title="Outbound connections Skynet dropped because the destination is on its blocklist, from its log lines"><div class="k">Blocked out</div><div class="v num"><span id="tc_bout">-</span><small>/min</small></div></div>
    <div title="All packets Skynet dropped, in and out, from its firewall counters (includes packets it does not log)"><div class="k">Skynet drops</div><div class="v num"><span id="tc_sky">-</span><small>/min</small></div></div>
    <div title="Connections to or from addresses IOCMON has alerted on"><div class="k">Flagged</div><div class="v num"><span id="tc_flag">-</span><small>/min</small></div></div>
  </div>
  <div class="tvfilters">
    <label><input type="checkbox" id="tf_in" checked onchange="tvfilter();"/>Inbound</label>
    <label><input type="checkbox" id="tf_out" checked onchange="tvfilter();"/>Outbound</label>
    <label><input type="checkbox" id="tf_ok" checked onchange="tvfilter();"/>Allowed</label>
    <label title="Dropped by the router's firewall or by Skynet"><input type="checkbox" id="tf_blk" checked onchange="tvfilter();"/>Blocked</label>
    <label title="Show DNS lookups (port 53 and 853) on the map and in the feed. Lookups to flagged addresses always show."><input type="checkbox" id="tf_dns" onchange="tvfilter();"/>DNS lookups</label>
    <label><input type="checkbox" id="tf_flag" onchange="tvfilter();"/>Flagged only</label>
  </div>
  <div class="banner red tvalert" id="tv_alert"><span id="tv_alert_t" style="flex:1"></span><a class="btn ack" id="tv_ack" onclick="tvack();">Acknowledge</a></div>
  <div class="tvpanel" id="tv_panel">
    <a class="tvdrawbtn" id="tv_drawbtn" onclick="tvdrawer();"></a>
    <div class="tabs">
      <a id="tvt_feed" class="sel" onclick="tvtab('feed');">Live Feed</a>
      <a id="tvt_top" onclick="tvtab('top');">Top Countries</a>
      <a id="tvt_replay" onclick="tvtab('replay');">Replay</a>
    </div>
    <div id="tvp_feed" class="tvfeed"></div>
    <div id="tvp_key" class="tvkey"><b>ALLOWED</b> went through &nbsp;|&nbsp; <b>FIREWALL</b> dropped by the router's firewall <span id="tvp_keysky">&nbsp;|&nbsp; <b>SKYNET</b> dropped by Skynet's blocklist</span></div>
    <div id="tvp_top" class="tvtop" style="display:none"><div><h3>Inbound, last 15 min</h3><div id="tv_topin"></div></div><div><h3>Outbound, last 15 min</h3><div id="tv_topout"></div></div></div>
    <div id="tvp_replay" class="tvreplay" style="display:none">
      <div class="plain off" id="tv_rinfo">Samples are kept in this browser for 15 minutes while Threat View is open.</div>
      <input type="range" id="tv_rpos" min="0" max="0" value="0" oninput="tvrlabel();"/>
      <div class="tools"><span class="num" id="tv_rlabel" style="flex:1">-</span>
        <select id="tv_rspeed"><option value="1">1x</option><option value="4" selected>4x</option><option value="16">16x</option></select>
        <a class="btn" onclick="tvreplay();">Play From Here</a><a class="btn" onclick="tvlive();">Back to Live</a></div>
    </div>
  </div>
  </div>
  <div class="tvfoot"><span>Home: <span id="tv_home">-</span> <a onclick="tvsethome();">change</a></span><span>IP address data powered by <a href="https://www.iplocate.io" target="_blank" rel="noopener noreferrer">IPLocate.io</a> (CC BY-SA 4.0) | Map: Natural Earth</span></div>
</div>

<div class="modal" id="m_box" style="display:none"><div class="mbox">
  <div class="mt" id="m_title"></div><div id="m_text"></div><div class="mwarn" id="m_warn"></div>
  <div class="mbtns"><a class="btn" id="m_ok" onclick="okask();">OK</a><a class="btn" onclick="closeask();">Cancel</a></div>
</div></div>

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
<!-- Signed: 2026-11-21 14:12:20 UTC (v1.6.4) -->
<!--
#-----BEGIN SIGNATURE-----
#MEUCIF5h6JCgDIajkDw55R2BC/Us+hsuwDbtLiIyaG3geYYSAiEA/Nvst+eWwZ4b
#TDIJbWZHC0sG+1bn5nEbOjmsg7wsBEg=
#-----END SIGNATURE-----
-->
