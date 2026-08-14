---
layout: page
title: About
icon: fas fa-user
order: 6
permalink: /about/
---

<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">

<div class="og">

<section class="og-console" id="og-console">
  <div class="og-console-bar">
    <span class="og-dot"></span><span class="og-dot"></span><span class="og-dot"></span>
    <span class="og-console-label">analyst-profile</span>
    <span class="og-pulse" id="og-clock">--:--:-- EAT</span>
  </div>

  <div class="og-console-body">
    <div class="og-id">
      <div class="og-avatar">
        <img src="/assets/img/Ongalo.jpg" alt="Ongalo Glenn">
        <span class="og-live"></span>
      </div>
      <div class="og-id-text">
        <h1 class="og-name">Ongalo&nbsp;Glenn</h1>
        <p class="og-role"><span class="og-arrow">&gt;</span> <span id="og-type"></span><span class="og-caret"></span></p>
        <div class="og-tags">
          <span class="og-chip og-chip-live">OPEN TO WORK</span>
          <span class="og-chip">Nairobi, KE</span>
          <span class="og-chip">UTC+3</span>
        </div>
      </div>
    </div>

    <div class="og-metrics">
      <div class="og-metric"><div class="og-metric-n" data-to="42">0</div><div class="og-metric-l">Articles<br>published</div></div>
      <div class="og-metric"><div class="og-metric-n" data-to="3">0</div><div class="og-metric-l">HTB machines<br>rooted</div></div>
      <div class="og-metric"><div class="og-metric-n" data-to="18">0</div><div class="og-metric-l">OverTheWire<br>Bandit level</div></div>
      <div class="og-metric"><div class="og-metric-n" data-to="7">0</div><div class="og-metric-l">Weeks on IT<br>audit fieldwork</div></div>
    </div>
  </div>
</section>

<section class="og-sec og-rise">
  <p class="og-eyebrow">Summary</p>
  <p class="og-brief">
    I hunt threats, investigate breaches, and build the detection logic that catches what automated tools miss.
  </p>
  <p class="og-body">
    I run IT infrastructure and cyber risk consulting at <strong>Digi Africa</strong>, working with betting and gaming operators on cyber insurance risk, <strong>AML and CTF compliance</strong>, and incident response for fiduciary data leaks. I graduated top of my class from <strong>Cyber Shujaa</strong> and recently spent seven weeks on an IT audit engagement with a cyber risk management firm, testing control environments across client technology estates.
  </p>
  <p class="og-body">
    I am looking for a <strong>SOC Analyst</strong> role on a team that takes detection engineering seriously. Everything below is verifiable. The lab writeups and articles on this site are the working notes.
  </p>
</section>

<section class="og-sec og-rise">
  <div class="og-sec-head">
    <p class="og-eyebrow">Event feed</p>
    <div class="og-filters">
      <button class="og-f on" data-f="all">All</button>
      <button class="og-f" data-f="role">Roles</button>
      <button class="og-f" data-f="lab">Labs</button>
      <button class="og-f" data-f="cert">Training</button>
    </div>
  </div>
  <p class="og-hint">Newest first. Select a row to expand.</p>
  <div class="og-feed" id="og-feed"></div>
</section>

<section class="og-sec og-rise">
  <p class="og-eyebrow">Capability matrix</p>
  <p class="og-hint">Grouped by function. Depth of fill reflects how much of it I have actually done, not how many courses I have watched.</p>
  <div class="og-matrix" id="og-matrix"></div>
  <div class="og-legend">
    <span><i class="og-sw l3"></i>Working depth</span>
    <span><i class="og-sw l2"></i>Practised</span>
    <span><i class="og-sw l1"></i>Building</span>
  </div>
</section>

<section class="og-sec og-rise">
  <p class="og-eyebrow">Currently</p>
  <ul class="og-now">
    <li><span class="og-now-tick"></span>OverTheWire Bandit, levels 17 to 18. SSH keys and privilege escalation.</li>
    <li><span class="og-now-tick"></span>Blue Team Labs Online defensive scenarios.</li>
    <li><span class="og-now-tick"></span>Building detection use cases mapped to MITRE ATT&amp;CK.</li>
    <li><span class="og-now-tick"></span>Writing up every lab and incident I work through.</li>
  </ul>
</section>

<section class="og-cta og-rise">
  <div>
    <p class="og-cta-k">Hiring for a SOC or security analyst role?</p>
    <p class="og-cta-s">Nairobi based, open to remote. I reply to everything.</p>
  </div>
  <div class="og-cta-links">
    <a class="og-btn og-btn-p" href="mailto:ongaloglenn45@gmail.com">Email me</a>
    <a class="og-btn" href="/labs/">See the labs</a>
  </div>
</section>

</div>

<style>
.og{
  --ink:#0B1017; --ink2:#131C28;
  --signal:#FFB020; --trace:#4EC9E8; --ok:#3DD68C;
  --dim:#6B7F94; --pale:#C9D6E2;
  --disp:'Space Grotesk',system-ui,sans-serif;
  --mono:'JetBrains Mono',ui-monospace,monospace;
  --r:14px;
}
.og *{box-sizing:border-box}
.og{margin-top:-.5rem}

.og-console{
  background:var(--ink); border-radius:var(--r); overflow:hidden;
  border:1px solid rgba(255,255,255,.07);
  box-shadow:0 24px 60px -28px rgba(0,0,0,.65);
  margin-bottom:3.2rem;
}
.og-console-bar{
  display:flex; align-items:center; gap:7px;
  padding:11px 16px; background:#080D13;
  border-bottom:1px solid rgba(255,255,255,.06);
}
.og-dot{width:9px;height:9px;border-radius:50%;background:#2B3745}
.og-console-label{font-family:var(--mono);font-size:11px;color:var(--dim);margin-left:8px;letter-spacing:.5px}
.og-pulse{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--trace);letter-spacing:.5px}
.og-console-body{padding:30px 26px 26px}

.og-id{display:flex;align-items:center;gap:22px;flex-wrap:wrap}
.og-avatar{position:relative;flex-shrink:0}
.og-avatar img{width:96px;height:96px;border-radius:20px;object-fit:cover;border:1px solid rgba(255,255,255,.12);display:block}
.og-live{
  position:absolute;right:-3px;bottom:-3px;width:16px;height:16px;
  border-radius:50%;background:var(--ok);border:3px solid var(--ink);
  animation:ogBeat 2.4s ease-in-out infinite;
}
@keyframes ogBeat{0%,100%{box-shadow:0 0 0 0 rgba(61,214,140,.5)}50%{box-shadow:0 0 0 7px rgba(61,214,140,0)}}

.og-id-text{min-width:230px;flex:1}
.og-name{font-family:var(--disp);font-weight:700;font-size:clamp(1.7rem,5vw,2.35rem);color:#fff;margin:0 0 4px;letter-spacing:-.02em;line-height:1.05}
.og-role{font-family:var(--mono);font-size:.85rem;color:var(--pale);margin:0 0 13px;min-height:1.3em}
.og-arrow{color:var(--signal)}
.og-caret{display:inline-block;width:8px;height:15px;background:var(--signal);vertical-align:-2px;margin-left:2px;animation:ogBlink 1.05s steps(1) infinite}
@keyframes ogBlink{0%,50%{opacity:1}51%,100%{opacity:0}}

.og-tags{display:flex;gap:7px;flex-wrap:wrap}
.og-chip{font-family:var(--mono);font-size:10px;letter-spacing:.7px;padding:4px 10px;border-radius:20px;color:var(--dim);border:1px solid rgba(255,255,255,.1)}
.og-chip-live{color:var(--ok);border-color:rgba(61,214,140,.35);background:rgba(61,214,140,.08)}

.og-metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;margin-top:28px;background:rgba(255,255,255,.06);border-radius:10px;overflow:hidden}
.og-metric{background:var(--ink2);padding:16px 14px}
.og-metric-n{font-family:var(--disp);font-weight:700;font-size:1.9rem;color:var(--signal);line-height:1;letter-spacing:-.02em}
.og-metric-l{font-family:var(--mono);font-size:9.5px;color:var(--dim);margin-top:7px;line-height:1.45;letter-spacing:.3px}

.og-sec{margin-bottom:3.2rem}
.og-eyebrow{font-family:var(--mono);font-size:10px;letter-spacing:2.4px;text-transform:uppercase;opacity:.45;margin:0 0 14px}
.og-brief{font-family:var(--disp);font-weight:500;font-size:clamp(1.1rem,2.6vw,1.42rem);line-height:1.42;letter-spacing:-.015em;margin:0 0 18px}
.og-body{font-size:.95rem;line-height:1.72;opacity:.86;margin:0 0 14px}
.og-hint{font-family:var(--mono);font-size:11px;opacity:.4;margin:0 0 16px}

.og-sec-head{display:flex;justify-content:space-between;align-items:flex-start;gap:14px;flex-wrap:wrap}
.og-filters{display:flex;gap:5px;flex-wrap:wrap;margin-bottom:14px}
.og-f{
  font-family:var(--mono);font-size:10.5px;letter-spacing:.6px;
  padding:6px 13px;border-radius:20px;cursor:pointer;
  background:transparent;color:inherit;opacity:.42;
  border:1px solid var(--btn-border-color,rgba(128,128,128,.3));
  transition:all .18s;
}
.og-f:hover{opacity:.75}
.og-f.on{opacity:1;color:var(--signal);border-color:var(--signal);background:rgba(255,176,32,.09)}

.og-feed{border-top:1px solid var(--btn-border-color,rgba(128,128,128,.18))}
.og-ev{border-bottom:1px solid var(--btn-border-color,rgba(128,128,128,.18));cursor:pointer;transition:background .18s}
.og-ev:hover{background:rgba(128,128,128,.045)}
.og-ev-top{display:flex;align-items:center;gap:13px;padding:15px 4px}
.og-ev-date{font-family:var(--mono);font-size:10.5px;opacity:.42;min-width:60px;flex-shrink:0;letter-spacing:.3px}
.og-ev-kind{font-family:var(--mono);font-size:9px;font-weight:700;letter-spacing:1px;padding:3px 8px;border-radius:4px;flex-shrink:0}
.k-role{background:rgba(255,176,32,.14);color:#B87D0A}
.k-lab{background:rgba(78,201,232,.14);color:#1E86A3}
.k-cert{background:rgba(61,214,140,.14);color:#238B5B}
html[data-mode="dark"] .k-role{color:#FFB020}
html[data-mode="dark"] .k-lab{color:#4EC9E8}
html[data-mode="dark"] .k-cert{color:#3DD68C}
.og-ev-title{font-weight:600;font-size:.92rem;flex:1;line-height:1.35}
.og-ev-org{font-size:.78rem;opacity:.5;display:block;margin-top:2px;font-weight:400}
.og-ev-x{font-family:var(--mono);font-size:13px;opacity:.3;flex-shrink:0;transition:transform .22s,opacity .22s}
.og-ev.open .og-ev-x{transform:rotate(90deg);opacity:.7}
.og-ev-detail{max-height:0;overflow:hidden;transition:max-height .32s ease}
.og-ev.open .og-ev-detail{max-height:660px}
.og-ev-inner{padding:0 4px 20px 76px;font-size:.88rem;line-height:1.68;opacity:.82}
.og-ev-inner ul{margin:0;padding-left:17px}
.og-ev-inner li{margin-bottom:5px}
.og-ev-inner code{font-size:.85em}
@media(max-width:560px){.og-ev-inner{padding-left:4px}}

.og-matrix{display:grid;grid-template-columns:repeat(auto-fit,minmax(158px,1fr));gap:11px}
.og-col{border:1px solid var(--btn-border-color,rgba(128,128,128,.2));border-radius:10px;padding:13px}
.og-col-h{font-family:var(--mono);font-size:9.5px;letter-spacing:1.3px;text-transform:uppercase;opacity:.4;margin-bottom:10px}
.og-cell{font-size:.79rem;padding:6px 9px;border-radius:6px;margin-bottom:5px;border-left:2px solid transparent;transition:all .18s;cursor:default}
.og-cell:last-child{margin-bottom:0}
.og-cell.l3{background:rgba(255,176,32,.13);border-left-color:#FFB020}
.og-cell.l2{background:rgba(255,176,32,.07);border-left-color:rgba(255,176,32,.5)}
.og-cell.l1{background:rgba(128,128,128,.06);border-left-color:rgba(128,128,128,.35)}
.og-cell:hover{transform:translateX(3px)}
.og-legend{display:flex;gap:16px;flex-wrap:wrap;margin-top:14px;font-family:var(--mono);font-size:10px;opacity:.5}
.og-legend span{display:flex;align-items:center;gap:6px}
.og-sw{width:11px;height:11px;border-radius:3px;display:inline-block}
.og-sw.l3{background:#FFB020}
.og-sw.l2{background:rgba(255,176,32,.5)}
.og-sw.l1{background:rgba(128,128,128,.4)}

.og-now{list-style:none;padding:0;margin:0}
.og-now li{display:flex;align-items:flex-start;gap:11px;padding:10px 0;font-size:.9rem;line-height:1.6;border-bottom:1px solid var(--btn-border-color,rgba(128,128,128,.14))}
.og-now li:last-child{border-bottom:none}
.og-now-tick{width:6px;height:6px;border-radius:50%;background:#FFB020;margin-top:8px;flex-shrink:0}

.og-cta{display:flex;justify-content:space-between;align-items:center;gap:20px;flex-wrap:wrap;padding:24px;border-radius:var(--r);background:var(--ink);border:1px solid rgba(255,255,255,.07)}
.og-cta-k{font-family:var(--disp);font-weight:700;font-size:1.06rem;color:#fff;margin:0 0 4px}
.og-cta-s{font-family:var(--mono);font-size:11.5px;color:var(--dim);margin:0}
.og-cta-links{display:flex;gap:9px;flex-wrap:wrap}
.og-btn{font-family:var(--mono);font-size:11.5px;letter-spacing:.4px;padding:10px 20px;border-radius:8px;text-decoration:none;border:1px solid rgba(255,255,255,.16);color:var(--pale);transition:all .18s;white-space:nowrap}
.og-btn:hover{border-color:var(--pale);color:#fff}
.og-btn-p{background:#FFB020;border-color:#FFB020;color:#0B1017;font-weight:700}
.og-btn-p:hover{background:#FFC24D;border-color:#FFC24D;color:#0B1017}

.og-rise{opacity:0;transform:translateY(18px);transition:opacity .55s ease,transform .55s ease}
.og-rise.in{opacity:1;transform:none}

@media(max-width:640px){
  .og-metrics{grid-template-columns:repeat(2,1fr)}
  .og-console-body{padding:24px 18px 20px}
  .og-ev-title{font-size:.87rem}
}
@media(prefers-reduced-motion:reduce){
  .og-rise{opacity:1;transform:none;transition:none}
  .og-live,.og-caret{animation:none}
  .og-ev-detail{transition:none}
}
</style>

<script>
(function(){
  var root=document.querySelector('.og');
  if(!root) return;
  var slow=window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function tick(){
    var d=new Date(new Date().toLocaleString('en-US',{timeZone:'Africa/Nairobi'}));
    var p=function(n){return String(n).padStart(2,'0')};
    var el=document.getElementById('og-clock');
    if(el) el.textContent=p(d.getHours())+':'+p(d.getMinutes())+':'+p(d.getSeconds())+' EAT';
  }
  tick(); setInterval(tick,1000);

  var ROLES=['SOC Analyst','Threat detection and incident response','AML and CTF compliance','Head of IT Infrastructure, Digi Africa'];
  var t=document.getElementById('og-type');
  if(t){
    if(slow){ t.textContent=ROLES[0]; }
    else{
      var ri=0,ci=0,del=false;
      (function loop(){
        var s=ROLES[ri];
        t.textContent=del?s.slice(0,--ci):s.slice(0,++ci);
        var w=del?38:62;
        if(!del&&ci===s.length){w=2100;del=true}
        else if(del&&ci===0){del=false;ri=(ri+1)%ROLES.length;w=380}
        setTimeout(loop,w);
      })();
    }
  }

  var EV=[
    {d:'2026-08',k:'cert',kl:'AUDIT',t:'IT audit engagement, 7 weeks',o:'Cyber risk management firm',
     h:'<ul><li>Tested design and operating effectiveness of controls across access management, change management, backup and recovery, and third-party governance.</li><li>Evidence-based sampling across a review period rather than point-in-time checks.</li><li>Wrote findings with risk ratings and agreed management responses.</li><li>Two writeups on this site cover the engagement and the skills it built.</li></ul>'},
    {d:'2026-06',k:'lab',kl:'LAB',t:'HTB Cap, rooted',o:'Hack The Box',
     h:'IDOR on a web dashboard exposed a PCAP containing plaintext FTP credentials. Password reuse gave SSH access. A <code>cap_setuid</code> capability on Python 3.8 escalated to root. Full writeup with the attack chain is in Labs.'},
    {d:'2026-06',k:'lab',kl:'LAB',t:'HTB Sherlock: Brutus, DFIR',o:'Hack The Box',
     h:'Reconstructed a full Linux compromise timeline from <code>auth.log</code> and <code>wtmp</code>. Brute force through to backdoor account creation and a persistence script download. Mapped to MITRE T1136.001.'},
    {d:'2026-06',k:'lab',kl:'LAB',t:'HTB Redeemer, rooted',o:'Hack The Box',
     h:'Unauthenticated Redis on port 6379, missed entirely by the default nmap scan. The lesson that stuck: always run <code>-p-</code>.'},
    {d:'2026-03',k:'role',kl:'ROLE',t:'Head of IT Infrastructure and Innovation',o:'Digi Africa, subsidiary of MGA Group',
     h:'<ul><li>Lead infrastructure strategy and security operations.</li><li>Cyber insurance risk consulting for betting and gaming operators.</li><li>AML and CTF compliance, including suspicious pattern identification and regulatory adherence.</li><li>Incident response for fiduciary data leaks: investigation, containment, and post-incident reporting.</li><li>Third-party risk and control assessments for clients in a high-regulation sector.</li></ul>'},
    {d:'2026-02',k:'cert',kl:'CERT',t:'Cyber Shujaa, Security Analyst track',o:'Graduated top of class',
     h:'Network security, application security, cloud security, incident response, security architecture, IoT security, and digital forensics. Selected through a competitive national process.'},
    {d:'2024-11',k:'role',kl:'ROLE',t:'Research Analyst',o:'MGA Group',
     h:'<ul><li>Investigated complex datasets for patterns, anomalies, and risk indicators.</li><li>Built statistical models in Python and R for predictive analysis and risk scoring.</li><li>Produced structured risk reports and compliance documentation for senior stakeholders.</li></ul>'},
    {d:'2024-01',k:'role',kl:'ROLE',t:'Data Analyst',o:'House of Procurement',
     h:'Multi-source data analysis, Tableau and Power BI dashboards, and root cause investigations that improved process efficiency by 30%.'},
    {d:'2023-12',k:'cert',kl:'EDU',t:'BSc Business Information Technology',o:'Jomo Kenyatta University of Agriculture and Technology',
     h:'Four-year degree covering systems analysis, databases, networking, and business process design.'}
  ];

  var feed=document.getElementById('og-feed');
  if(feed){
    feed.innerHTML=EV.map(function(e){
      return '<div class="og-ev" data-k="'+e.k+'">'+
        '<div class="og-ev-top">'+
          '<span class="og-ev-date">'+e.d+'</span>'+
          '<span class="og-ev-kind k-'+e.k+'">'+e.kl+'</span>'+
          '<span class="og-ev-title">'+e.t+'<span class="og-ev-org">'+e.o+'</span></span>'+
          '<span class="og-ev-x">&#9656;</span>'+
        '</div>'+
        '<div class="og-ev-detail"><div class="og-ev-inner">'+e.h+'</div></div>'+
      '</div>';
    }).join('');
    feed.addEventListener('click',function(ev){
      var row=ev.target.closest('.og-ev');
      if(row) row.classList.toggle('open');
    });
  }

  root.querySelectorAll('.og-f').forEach(function(b){
    b.addEventListener('click',function(){
      root.querySelectorAll('.og-f').forEach(function(x){x.classList.remove('on')});
      b.classList.add('on');
      var f=b.dataset.f;
      root.querySelectorAll('.og-ev').forEach(function(r){
        r.style.display=(f==='all'||r.dataset.k===f)?'':'none';
      });
    });
  });

  var MX=[
    {h:'Detection &amp; response',c:[['Log analysis',3],['Alert triage',3],['Incident response',3],['DFIR',2],['Threat hunting',2],['SIEM (Splunk, Wazuh)',2]]},
    {h:'Risk &amp; compliance',c:[['AML / CTF',3],['Cyber insurance risk',3],['IT audit &amp; controls',3],['Third-party risk',2],['Data Protection Act',2]]},
    {h:'Networks &amp; systems',c:[['TCP/IP &amp; DNS',3],['Packet analysis',2],['Linux',2],['Windows event logs',2],['Nmap &amp; enumeration',2]]},
    {h:'Frameworks',c:[['MITRE ATT&amp;CK',3],['Cyber Kill Chain',3],['Zero Trust',2],['NIST CSF',1]]},
    {h:'Code &amp; data',c:[['Python',3],['SQL',2],['R',2],['Bash',2],['Power BI / Tableau',3]]},
    {h:'Cloud',c:[['Entra ID / IAM',2],['Cloud logging',2],['Posture management',1]]}
  ];
  var mx=document.getElementById('og-matrix');
  if(mx){
    mx.innerHTML=MX.map(function(col){
      return '<div class="og-col"><div class="og-col-h">'+col.h+'</div>'+
        col.c.map(function(c){return '<div class="og-cell l'+c[1]+'">'+c[0]+'</div>'}).join('')+
      '</div>';
    }).join('');
  }

  function countUp(el){
    var to=+el.dataset.to,cur=0,step=Math.max(1,Math.round(to/28));
    if(slow){el.textContent=to;return}
    var iv=setInterval(function(){
      cur+=step;
      if(cur>=to){cur=to;clearInterval(iv)}
      el.textContent=cur;
    },34);
  }

  if('IntersectionObserver' in window){
    var io=new IntersectionObserver(function(es){
      es.forEach(function(e){
        if(!e.isIntersecting) return;
        e.target.classList.add('in');
        var ns=e.target.querySelectorAll('.og-metric-n');
        if(ns.length) ns.forEach(countUp);
        io.unobserve(e.target);
      });
    },{threshold:.12});
    root.querySelectorAll('.og-rise').forEach(function(x){io.observe(x)});
    var c=document.getElementById('og-console');
    if(c) io.observe(c);
  } else {
    root.querySelectorAll('.og-rise').forEach(function(x){x.classList.add('in')});
    root.querySelectorAll('.og-metric-n').forEach(function(x){x.textContent=x.dataset.to});
  }
})();
</script>
