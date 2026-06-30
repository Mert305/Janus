"""
Honeypot Erken Uyarı Sistemi - Web Dashboard
=============================================
Flask tabanlı gerçek zamanlı izleme paneli.
Alarm, olay ve analiz verilerini görselleştirir.
"""

import json
import threading
import time
import os
from datetime import datetime

try:
    from flask import Flask, render_template_string, jsonify
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

from logger import HoneypotLogger
from analyzer import Analyzer
from alert_engine import AlertEngine


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Janus &mdash; Honeypot Erken Uyari Sistemi</title>
<style>
:root {
  --bg:       #0b0e17;  --surface:  #131829;  --card:     #181d30;
  --border:   #232940;  --txt:      #c9d1d9;  --dim:      #6e7681;
  --accent:   #58a6ff;  --green:    #3fb950;  --red:      #f85149;
  --orange:   #d29922;  --purple:   #bc8cff;  --cyan:     #39d2c0;
  --radius:   12px;
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--txt);min-height:100vh}

/* === HEADER ====================================================== */
.topbar{
  display:flex;align-items:center;justify-content:space-between;
  padding:14px 28px;
  background:linear-gradient(135deg,#0d1b2a 0%,#1b2838 100%);
  border-bottom:1px solid var(--border);
  position:sticky;top:0;z-index:50;backdrop-filter:blur(12px);
}
.topbar .brand{display:flex;align-items:center;gap:12px}
.topbar .brand svg{width:32px;height:32px}
.topbar .brand h1{font-size:1.15rem;font-weight:700;color:#fff;letter-spacing:.3px}
.topbar .brand span{font-size:.75rem;color:var(--dim);font-weight:400}
.topbar .controls{display:flex;align-items:center;gap:14px}
.live-badge{display:flex;align-items:center;gap:6px;padding:5px 12px;
  border-radius:20px;background:rgba(63,185,80,.12);font-size:.78rem;
  color:var(--green);font-weight:600;letter-spacing:.5px}
.live-badge .dot{width:7px;height:7px;border-radius:50%;background:var(--green);
  animation:blink 1.8s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
.btn{background:var(--surface);color:var(--accent);border:1px solid var(--border);
  padding:6px 14px;border-radius:8px;cursor:pointer;font-size:.8rem;
  transition:all .2s ease}
.btn:hover{background:var(--border);border-color:var(--accent)}
.toggle-label{display:flex;align-items:center;gap:6px;font-size:.78rem;color:var(--dim);cursor:pointer}
.toggle-label input{accent-color:var(--accent)}

/* === GRID ======================================================== */
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;padding:20px 28px}
@media(max-width:1100px){.grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:600px){.grid{grid-template-columns:1fr;padding:12px}}
.span2{grid-column:span 2}
.span3{grid-column:span 3}
.span4{grid-column:span 4}

/* === CARDS ======================================================= */
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);
  padding:20px;transition:border-color .25s ease;overflow:hidden}
.card:hover{border-color:rgba(88,166,255,.25)}
.card-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
.card-head h2{font-size:.92rem;font-weight:600;color:#fff;display:flex;align-items:center;gap:8px}
.card-head .badge{font-size:.7rem;padding:2px 8px;border-radius:10px;font-weight:600}

/* === STAT CARDS ================================================== */
.stat-card{text-align:center;position:relative;overflow:hidden}
.stat-card .icon{font-size:1.6rem;margin-bottom:6px}
.stat-card .number{font-size:2.4rem;font-weight:800;line-height:1.1;
  background:linear-gradient(135deg,var(--c1),var(--c2));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  background-clip:text}
.stat-card .label{font-size:.78rem;color:var(--dim);margin-top:4px}
.stat-card::after{content:'';position:absolute;inset:0;
  background:radial-gradient(circle at 50% 120%,var(--glow) 0%,transparent 65%);
  opacity:.07;pointer-events:none}

/* === TABLE ======================================================= */
table{width:100%;border-collapse:separate;border-spacing:0}
thead th{text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.6px;
  color:var(--dim);padding:8px 10px;border-bottom:1px solid var(--border);font-weight:600}
tbody td{padding:7px 10px;font-size:.82rem;border-bottom:1px solid rgba(35,41,64,.6);
  vertical-align:middle}
tbody tr:hover td{background:rgba(88,166,255,.04)}

/* === ALERT ITEMS ================================================= */
.alert-row{display:flex;align-items:flex-start;gap:10px;padding:10px 12px;
  margin-bottom:6px;border-radius:8px;border-left:3px solid;
  transition:background .15s ease;font-size:.82rem}
.alert-row:hover{background:rgba(255,255,255,.02)}
.alert-row.critical{border-color:var(--red);background:rgba(248,81,73,.05)}
.alert-row.high{border-color:var(--orange);background:rgba(210,153,34,.05)}
.alert-row.medium{border-color:var(--purple);background:rgba(188,140,255,.04)}
.alert-row.low{border-color:var(--green);background:rgba(63,185,80,.04)}
.alert-sev{font-size:.65rem;font-weight:700;padding:2px 7px;border-radius:4px;
  text-transform:uppercase;letter-spacing:.5px;flex-shrink:0;margin-top:2px}
.sev-critical{background:rgba(248,81,73,.18);color:var(--red)}
.sev-high{background:rgba(210,153,34,.18);color:var(--orange)}
.sev-medium{background:rgba(188,140,255,.15);color:var(--purple)}
.sev-low{background:rgba(63,185,80,.15);color:var(--green)}
.alert-body{flex:1;min-width:0}
.alert-body .meta{display:flex;align-items:center;gap:8px;margin-bottom:3px;flex-wrap:wrap}
.alert-body .meta .type{font-weight:600;color:#fff}
.alert-body .meta .ip{color:var(--cyan);font-family:'Cascadia Code','Fira Code',monospace;font-size:.78rem}
.alert-body .meta .time{color:var(--dim);font-size:.72rem;margin-left:auto}
.alert-body .desc{color:var(--dim);font-size:.78rem;line-height:1.4}

/* === EVENT LOG =================================================== */
.log-scroll{max-height:420px;overflow-y:auto;scrollbar-width:thin;
  scrollbar-color:var(--border) transparent}
.log-scroll::-webkit-scrollbar{width:5px}
.log-scroll::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
.log-line{display:flex;align-items:center;gap:8px;padding:5px 8px;
  border-radius:6px;font-family:'Cascadia Code','Fira Code',monospace;font-size:.78rem;
  margin-bottom:2px;transition:background .12s}
.log-line:hover{background:rgba(88,166,255,.06)}
.log-time{color:var(--dim);flex-shrink:0;font-size:.72rem;min-width:62px}
.svc-tag{padding:1px 6px;border-radius:4px;font-size:.65rem;font-weight:700;
  text-transform:uppercase;letter-spacing:.4px;flex-shrink:0}
.svc-ssh{background:rgba(57,210,192,.12);color:var(--cyan)}
.svc-ftp{background:rgba(188,140,255,.12);color:var(--purple)}
.svc-http{background:rgba(210,153,34,.12);color:var(--orange)}
.log-type{color:var(--accent);font-weight:600;flex-shrink:0}
.log-detail{color:var(--dim);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* === CMD LOG ===================================================== */
.cmd-line{display:flex;align-items:center;gap:8px;padding:6px 10px;
  border-radius:6px;font-family:'Cascadia Code','Fira Code',monospace;
  font-size:.78rem;margin-bottom:3px;transition:background .12s;
  border-left:3px solid transparent}
.cmd-line:hover{background:rgba(63,185,80,.06)}
.cmd-line.cmd-danger{border-left-color:var(--red);background:rgba(248,81,73,.04)}
.cmd-line.cmd-warn{border-left-color:var(--orange);background:rgba(210,153,34,.04)}
.cmd-line.cmd-access{border-left-color:var(--purple);background:rgba(188,140,255,.03)}
.cmd-line.cmd-normal{border-left-color:var(--border)}
.cmd-ip{color:var(--cyan);flex-shrink:0}
.cmd-arrow{color:var(--dim)}
.cmd-text{font-weight:600;word-break:break-all}
.cmd-text.ct-shell{color:var(--red)}
.cmd-text.ct-login{color:var(--orange)}
.cmd-text.ct-file{color:var(--purple)}
.cmd-text.ct-nav{color:var(--accent)}
.cmd-text.ct-normal{color:var(--green)}
.cmd-cat{font-size:.6rem;font-weight:700;padding:1px 5px;border-radius:3px;
  text-transform:uppercase;letter-spacing:.4px;flex-shrink:0;margin-right:2px}
.cmd-cat.cc-shell{background:rgba(248,81,73,.15);color:var(--red)}
.cmd-cat.cc-login{background:rgba(210,153,34,.15);color:var(--orange)}
.cmd-cat.cc-file{background:rgba(188,140,255,.12);color:var(--purple)}
.cmd-cat.cc-nav{background:rgba(88,166,255,.12);color:var(--accent)}
.cmd-cat.cc-normal{background:rgba(63,185,80,.1);color:var(--green)}
.cmd-terminal{background:#0a0d14;border:1px solid var(--border);border-radius:8px;
  padding:6px 4px}
.cmd-terminal .term-header{display:flex;align-items:center;gap:6px;padding:2px 8px 6px;
  border-bottom:1px solid var(--border);margin-bottom:6px}
.cmd-terminal .term-dots{display:flex;gap:4px}
.cmd-terminal .term-dots span{width:8px;height:8px;border-radius:50%}
.cmd-terminal .term-title{font-size:.7rem;color:var(--dim);font-family:'Cascadia Code','Fira Code',monospace}
.cmd-counter{display:flex;align-items:center;gap:14px;margin-bottom:10px;flex-wrap:wrap}
.cmd-counter .cc-item{display:flex;align-items:center;gap:5px;font-size:.72rem;color:var(--dim)}
.cmd-counter .cc-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}

/* === IP BAR ====================================================== */
.ip-bar-row{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.ip-bar-row .ip{font-family:'Cascadia Code','Fira Code',monospace;font-size:.8rem;
  color:var(--cyan);min-width:120px;flex-shrink:0}
.ip-bar-row .bar-wrap{flex:1;height:20px;background:var(--surface);border-radius:4px;overflow:hidden}
.ip-bar-row .bar{height:100%;border-radius:4px;
  background:linear-gradient(90deg,var(--accent),var(--purple));
  transition:width .5s ease}
.ip-bar-row .count{font-size:.78rem;color:var(--dim);min-width:36px;text-align:right}

/* === SEVERITY PIE (CSS-ONLY) ===================================== */
.sev-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:4px}
.sev-chip{display:flex;align-items:center;gap:8px;padding:8px 10px;
  border-radius:8px;background:var(--surface)}
.sev-chip .dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.sev-chip .lbl{font-size:.78rem;color:var(--dim);flex:1}
.sev-chip .cnt{font-size:1rem;font-weight:700}

/* === FOOTER ====================================================== */
.footer{text-align:center;padding:12px;font-size:.7rem;color:var(--dim);
  border-top:1px solid var(--border);margin-top:8px}
</style>
</head>
<body>

<!-- HEADER -->
<div class="topbar">
 <div class="brand">
  <svg viewBox="0 0 48 48" fill="none"><circle cx="24" cy="24" r="22" stroke="#58a6ff" stroke-width="2.5"/>
   <path d="M24 12 L32 20 L28 20 L28 32 L20 32 L20 20 L16 20 Z" fill="#58a6ff" opacity=".85"/></svg>
  <div><h1>Janus <span>Honeypot Erken Uyari Sistemi</span></h1></div>
 </div>
 <div class="controls">
  <div class="live-badge"><span class="dot"></span>CANLI</div>
  <button class="btn" onclick="refreshAll()">&#x21bb; Yenile</button>
  <label class="toggle-label">
   <input type="checkbox" id="autoRefresh" checked onchange="toggleAutoRefresh()"> Oto 5s
  </label>
 </div>
</div>

<div class="grid">

 <!-- ===== STAT CARDS ===== -->
 <div class="card stat-card" style="--c1:#58a6ff;--c2:#39d2c0;--glow:#58a6ff">
  <div class="icon">&#128202;</div>
  <div class="number" id="totalEvents">—</div>
  <div class="label">Toplam Olay</div>
 </div>
 <div class="card stat-card" style="--c1:#f85149;--c2:#d29922;--glow:#f85149">
  <div class="icon">&#128680;</div>
  <div class="number" id="totalAlerts">—</div>
  <div class="label">Toplam Alarm</div>
 </div>
 <div class="card stat-card" style="--c1:#d29922;--c2:#bc8cff;--glow:#d29922">
  <div class="icon">&#128187;</div>
  <div class="number" id="totalCommands">—</div>
  <div class="label">Toplam Komut</div>
 </div>
 <div class="card stat-card" style="--c1:#bc8cff;--c2:#58a6ff;--glow:#bc8cff">
  <div class="icon">&#127760;</div>
  <div class="number" id="uniqueIPs">—</div>
  <div class="label">Benzersiz IP</div>
 </div>

 <!-- ===== SON ALARMLAR ===== -->
 <div class="card span3">
  <div class="card-head">
   <h2>&#128680; Son Alarmlar</h2>
   <span class="badge" id="alertBadge" style="background:rgba(248,81,73,.15);color:var(--red)">0</span>
  </div>
  <div class="log-scroll" id="alertsList"><p style="color:var(--dim)">Yukleniyor...</p></div>
 </div>

 <!-- ===== ALARM DAGILIMI ===== -->
 <div class="card">
  <div class="card-head"><h2>&#128200; Alarm Dagilimi</h2></div>
  <div id="alertStats"><p style="color:var(--dim)">Yukleniyor...</p></div>
 </div>

 <!-- ===== SON OLAYLAR ===== -->
 <div class="card span3">
  <div class="card-head"><h2>&#128203; Son Olaylar</h2></div>
  <div class="log-scroll" id="eventsList"><p style="color:var(--dim)">Yukleniyor...</p></div>
 </div>

 <!-- ===== EN AKTIF IP'LER ===== -->
 <div class="card">
  <div class="card-head"><h2>&#127919; En Aktif IP'ler</h2></div>
  <div id="topIPs"><p style="color:var(--dim)">Yukleniyor...</p></div>
 </div>

 <!-- ===== SON KOMUTLAR ===== -->
 <div class="card span4">
  <div class="card-head">
   <h2>&#128187; Son Calistirilan Komutlar</h2>
   <span class="badge" id="cmdBadge" style="background:rgba(63,185,80,.15);color:var(--green)">0</span>
  </div>
  <div class="cmd-counter" id="cmdCounter"></div>
  <div class="cmd-terminal">
   <div class="term-header">
    <div class="term-dots">
     <span style="background:#f85149"></span>
     <span style="background:#d29922"></span>
     <span style="background:#3fb950"></span>
    </div>
    <span class="term-title">honeypot-session ~</span>
   </div>
   <div class="log-scroll" id="commandsList" style="max-height:380px"><p style="color:var(--dim)">Yukleniyor...</p></div>
  </div>
 </div>

</div>

<div class="footer">Janus Honeypot &mdash; Tum veriler sahte ortamdan toplanmaktadir. Gercek sisteme erisim yoktur.</div>

<script>
let autoRefreshInterval=null;
const $=id=>document.getElementById(id);
async function fj(u){const r=await fetch(u);return r.json()}

function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
function svcClass(s){return 'svc-tag svc-'+(s||'').toLowerCase()}
function sevClass(s){return 'alert-sev sev-'+(s||'low')}

async function refreshAll(){
 try{
  /* ---- Stats ---- */
  const st=await fj('/api/stats');
  $('totalEvents').textContent=st.total_events||0;
  $('totalAlerts').textContent=st.total_alerts||0;
  $('totalCommands').textContent=st.total_commands||0;
  $('uniqueIPs').textContent=st.unique_ips||0;

  /* ---- Alarmlar ---- */
  const al=await fj('/api/alerts?n=20');
  const ab=$('alertBadge'); ab.textContent=al.length;
  const ad=$('alertsList');
  if(!al.length){ad.innerHTML='<p style="color:var(--dim)">Henuz alarm yok</p>';}
  else{ad.innerHTML=al.slice().reverse().map(a=>`
   <div class="alert-row ${a.severity||'low'}">
    <span class="${sevClass(a.severity)}">${(a.severity||'').toUpperCase()}</span>
    <div class="alert-body">
     <div class="meta">
      <span class="type">${esc(a.alert_type||'')}</span>
      <span class="ip">${esc(a.src_ip||'')}</span>
      <span class="time">${(a.timestamp||'').substring(0,19)}</span>
     </div>
     <div class="desc">${esc(a.description||'')}</div>
    </div>
   </div>`).join('');}

  /* ---- Alarm dagilimi ---- */
  const as2=await fj('/api/alert_stats');
  const sd=$('alertStats');
  const sevs={critical:0,high:0,medium:0,low:0};
  const colors={critical:'var(--red)',high:'var(--orange)',medium:'var(--purple)',low:'var(--green)'};
  if(as2.CRITICAL) sevs.critical=as2.CRITICAL;
  if(as2.HIGH) sevs.high=as2.HIGH;
  if(as2.MEDIUM) sevs.medium=as2.MEDIUM;
  if(as2.LOW) sevs.low=as2.LOW;
  let typeHtml='';
  for(const[k,v]of Object.entries(as2)){
   if(['total_alerts','--- Severity ---','CRITICAL','HIGH','MEDIUM','LOW'].includes(k))continue;
   if(v)typeHtml+=`<div style="display:flex;justify-content:space-between;padding:5px 0;
     border-bottom:1px solid var(--border);font-size:.82rem">
     <span style="color:var(--dim)">${esc(k)}</span><span style="font-weight:700">${v}</span></div>`;
  }
  sd.innerHTML=`
   <div class="sev-grid">
    ${Object.entries(sevs).map(([s,c])=>`
     <div class="sev-chip">
      <span class="dot" style="background:${colors[s]}"></span>
      <span class="lbl">${s.charAt(0).toUpperCase()+s.slice(1)}</span>
      <span class="cnt" style="color:${colors[s]}">${c}</span>
     </div>`).join('')}
   </div>
   <div style="margin-top:12px">${typeHtml||'<p style="color:var(--dim);font-size:.8rem">Veri yok</p>'}</div>`;

  /* ---- Olaylar ---- */
  const ev=await fj('/api/events?n=25');
  const ed=$('eventsList');
  if(!ev.length){ed.innerHTML='<p style="color:var(--dim)">Henuz olay yok</p>';}
  else{ed.innerHTML=ev.slice().reverse().map(e=>`
   <div class="log-line">
    <span class="log-time">${(e.timestamp||'').substring(11,19)}</span>
    <span class="${svcClass(e.service)}">${(e.service||'').toUpperCase()}</span>
    <span class="log-type">${esc(e.event_type||'')}</span>
    <span style="color:var(--cyan)">${esc(e.src_ip||'')}${e.src_port?':'+e.src_port:''}</span>
    <span class="log-detail">${e.details?esc(JSON.stringify(e.details)).substring(0,90):''}</span>
   </div>`).join('');}

  /* ---- Top IPs ---- */
  const ti=await fj('/api/top_ips');
  const td=$('topIPs');
  if(!ti.length){td.innerHTML='<p style="color:var(--dim)">Veri yok</p>';}
  else{
   const mx=ti[0].count||1;
   td.innerHTML=ti.map(x=>`
    <div class="ip-bar-row">
     <span class="ip">${esc(x.ip)}</span>
     <div class="bar-wrap"><div class="bar" style="width:${(x.count/mx*100).toFixed(0)}%"></div></div>
     <span class="count">${x.count}</span>
    </div>`).join('');
  }

  /* ---- Komutlar ---- */
  const cm=await fj('/api/commands?n=40');
  const cd=$('commandsList');
  const cb=$('cmdBadge'); cb.textContent=cm.length;
  const cc=$('cmdCounter');

  const SHELL_CMDS=['cat','whoami','id','uname','ls','pwd','ps','netstat','ifconfig',
   'wget','curl','rm','chmod','chown','kill','su','sudo','ssh','nc','ncat','python',
   'perl','php','bash','sh','nmap','find','grep','awk','sed','head','tail','more',
   'less','vi','nano','export','env','history','w','last','mount','df','du','free',
   'top','crontab','iptables','useradd','passwd','adduser','tar','zip','base64',
   'dd','mkfs','fdisk','tcpdump','strace','ltrace','gdb','gcc','make','git','scp',
   'ftp_cmd','telnet','ping','traceroute','dig','host','systemctl','service','apt',
   'yum','pip','npm','docker','kubectl'];
  const LOGIN_CMDS=['USER','PASS','AUTH'];
  const FILE_CMDS=['RETR','STOR','STOU','APPE','DELE','RMD','MKD','RNFR','RNTO','LIST','NLST','SIZE','MDTM'];
  const NAV_CMDS=['CWD','CDUP','PWD','TYPE'];

  function cmdCategory(cmd){
    const upper=cmd.split(/\s/)[0].toUpperCase();
    const lower=cmd.split(/\s/)[0].toLowerCase();
    if(SHELL_CMDS.includes(lower))return{cat:'shell',label:'SHELL',cls:'cmd-danger'};
    if(LOGIN_CMDS.includes(upper))return{cat:'login',label:'LOGIN',cls:'cmd-warn'};
    if(FILE_CMDS.includes(upper))return{cat:'file',label:'DOSYA',cls:'cmd-access'};
    if(NAV_CMDS.includes(upper))return{cat:'nav',label:'NAV',cls:'cmd-normal'};
    return{cat:'normal',label:'FTP',cls:'cmd-normal'};
  }

  if(!cm.length){
    cd.innerHTML='<p style="color:var(--dim)">Henuz komut yok</p>';
    cc.innerHTML='';
  }else{
    const counts={shell:0,login:0,file:0,nav:0,normal:0};
    cm.forEach(c=>{counts[cmdCategory(c.command||'').cat]++});
    cc.innerHTML=`
     <div class="cc-item"><span class="cc-dot" style="background:var(--red)"></span>Shell: <b>${counts.shell}</b></div>
     <div class="cc-item"><span class="cc-dot" style="background:var(--orange)"></span>Login: <b>${counts.login}</b></div>
     <div class="cc-item"><span class="cc-dot" style="background:var(--purple)"></span>Dosya: <b>${counts.file}</b></div>
     <div class="cc-item"><span class="cc-dot" style="background:var(--accent)"></span>Navigasyon: <b>${counts.nav}</b></div>
     <div class="cc-item"><span class="cc-dot" style="background:var(--green)"></span>Diger: <b>${counts.normal}</b></div>`;
    cd.innerHTML=cm.slice().reverse().map(c=>{
     const g=cmdCategory(c.command||'');
     return `<div class="cmd-line ${g.cls}">
      <span class="log-time">${(c.timestamp||'').substring(11,19)}</span>
      <span class="${svcClass(c.service)}">${(c.service||'').toUpperCase()}</span>
      <span class="cmd-ip">${esc(c.src_ip||'')}</span>
      <span class="cmd-cat cc-${g.cat}">${g.label}</span>
      <span class="cmd-arrow">&#9656;</span>
      <span class="cmd-text ct-${g.cat}">${esc(c.command||'')}</span>
     </div>`;}).join('');
  }
 }catch(e){console.error('Refresh:',e)}
}

function toggleAutoRefresh(){
 if($('autoRefresh').checked) autoRefreshInterval=setInterval(refreshAll,5000);
 else clearInterval(autoRefreshInterval);
}
refreshAll();
autoRefreshInterval=setInterval(refreshAll,5000);
</script>
</body>
</html>"""


class Dashboard:
    """Flask tabanlı web dashboard."""

    def __init__(self, config: dict, hp_logger: HoneypotLogger,
                 alert_engine: AlertEngine, analyzer: Analyzer,
                 sandbox_manager=None, correlation=None, threat_intel=None):
        if not FLASK_AVAILABLE:
            hp_logger.logger.warning(
                "Flask kurulamadı - Dashboard devre dışı. "
                "Kurulum: pip install flask"
            )
            self.enabled = False
            return

        dash_cfg = config.get("dashboard", {})
        self.enabled = dash_cfg.get("enabled", True)
        self.host = dash_cfg.get("bind_host", "127.0.0.1")
        self.port = dash_cfg.get("bind_port", 5000)

        self.hp_logger = hp_logger
        self.alert_engine = alert_engine
        self.analyzer = analyzer
        self.sandbox_manager = sandbox_manager
        self.correlation = correlation
        self.threat_intel = threat_intel

        self.app = Flask(__name__)
        self._setup_routes()

    def _setup_routes(self):
        app = self.app

        @app.route("/")
        def index():
            return render_template_string(DASHBOARD_HTML)

        @app.route("/api/stats")
        def api_stats():
            events = self.hp_logger.read_events(last_n=10000)
            alerts = self.hp_logger.read_alerts(last_n=5000)
            commands = self.hp_logger.read_commands(last_n=5000)
            # Filter out binary/TLS noise
            commands = [c for c in commands if c.get("command") and
                        all(ch == '\n' or ch == '\r' or ch == '\t' or (' ' <= ch <= '~')
                            for ch in c["command"])]
            from collections import Counter
            ip_counter = Counter(e.get("src_ip", "") for e in events)
            return jsonify({
                "total_events": len(events),
                "total_alerts": len(alerts),
                "total_commands": len(commands),
                "unique_ips": len(ip_counter),
            })

        @app.route("/api/alerts")
        def api_alerts():
            from flask import request
            n = min(int(request.args.get("n", 20)), 200)
            return jsonify(self.hp_logger.read_alerts(last_n=n))

        @app.route("/api/events")
        def api_events():
            from flask import request
            n = min(int(request.args.get("n", 30)), 200)
            return jsonify(self.hp_logger.read_events(last_n=n))

        @app.route("/api/commands")
        def api_commands():
            from flask import request
            n = min(int(request.args.get("n", 50)), 500)
            raw = self.hp_logger.read_commands(last_n=n)
            # Filter out binary/TLS noise (non-printable characters)
            cleaned = []
            for c in raw:
                cmd = c.get("command", "")
                if cmd and all(ch == '\n' or ch == '\r' or ch == '\t' or (' ' <= ch <= '~') for ch in cmd):
                    cleaned.append(c)
            return jsonify(cleaned[-n:])

        @app.route("/api/alert_stats")
        def api_alert_stats():
            from collections import Counter
            alerts = self.hp_logger.read_alerts(last_n=10000)
            type_counter = Counter(a.get("alert_type", "other") for a in alerts)
            severity_counter = Counter(a.get("severity", "unknown") for a in alerts)
            stats = {"total_alerts": len(alerts)}
            stats.update(type_counter)
            stats["--- Severity ---"] = ""
            stats.update({f"{k.upper()}": v for k, v in severity_counter.items()})
            return jsonify(stats)

        @app.route("/api/top_ips")
        def api_top_ips():
            events = self.hp_logger.read_events(last_n=10000)
            from collections import Counter
            ip_counter = Counter(
                e.get("src_ip", "")
                for e in events
                if e.get("src_ip") and e.get("src_ip") not in ("", "127.0.0.1")
            )
            return jsonify([
                {"ip": ip, "count": cnt}
                for ip, cnt in ip_counter.most_common(15)
            ])

        @app.route("/api/report")
        def api_report():
            path = self.analyzer.generate_html_report()
            return jsonify({"status": "ok", "report_path": path})

        @app.route("/api/sandboxes")
        def api_sandboxes():
            import time as _t
            if self.sandbox_manager is None:
                return jsonify({"enabled": False, "sessions": []})
            sessions = []
            try:
                with self.sandbox_manager._lock:
                    for sid, s in self.sandbox_manager.sessions.items():
                        sessions.append({
                            "session_id": sid,
                            "container_id": s.container_id[:12],
                            "src_ip": s.src_ip,
                            "src_port": s.src_port,
                            "started_at": s.started_at,
                            "age_sec": round(_t.time() - s.started_at, 1),
                            "closed": s.closed,
                        })
            except Exception as e:
                self.hp_logger.logger.debug("api_sandboxes: %s", e)
            return jsonify({
                "enabled": True,
                "max_concurrent": self.sandbox_manager.max_concurrent,
                "session_ttl_sec": self.sandbox_manager.session_ttl,
                "active": len(sessions),
                "sessions": sessions,
            })

        @app.route("/api/kill_chains")
        def api_kill_chains():
            if self.correlation is None:
                return jsonify({"enabled": False, "kill_chains": [], "stats": {}})
            try:
                return jsonify({
                    "enabled": True,
                    "kill_chains": self.correlation.get_kill_chains(),
                    "stats": self.correlation.get_stats(),
                    "all_sessions": self.correlation.get_all_sessions(),
                })
            except Exception as e:
                return jsonify({"error": str(e)})

        @app.route("/api/threat_intel/<ip>")
        def api_threat_intel(ip):
            if self.threat_intel is None:
                return jsonify({"enabled": False})
            try:
                return jsonify(self.threat_intel.enrich(ip))
            except Exception as e:
                return jsonify({"error": str(e)})

    def start(self):
        if not self.enabled:
            return

        import logging as stdlib_logging
        log = stdlib_logging.getLogger('werkzeug')
        log.setLevel(stdlib_logging.WARNING)

        self.hp_logger.logger.info(
            "Dashboard başlatılıyor: http://%s:%d", self.host, self.port
        )
        thread = threading.Thread(
            target=lambda: self.app.run(
                host=self.host, port=self.port, debug=False,
                use_reloader=False,
            ),
            name="dashboard",
            daemon=True,
        )
        thread.start()

    def stop(self):
        pass  # Flask daemon thread olarak kapanır
