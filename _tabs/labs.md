---
layout: page
title: Labs
icon: fas fa-flask
order: 2
permalink: /labs/
---

<link href="https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">

<div class="lb">

  <!-- blueprint field -->
  <div class="lb-blue"></div>

  <header class="lb-head">
    <div class="lb-hz"></div>
    <div class="lb-head-in">
      <p class="lb-eye">// facility log</p>
      <h1 class="lb-title">The Laboratory</h1>
      <p class="lb-sub">Every experiment run to completion, documented in full. Successes and dead ends both. If it is on this page, I broke it open and wrote down what was inside.</p>
    </div>

    <div class="lb-gauges">
      <div class="lb-g">
        <svg class="lb-flask" viewBox="0 0 40 52" aria-hidden="true">
          <path class="lb-glass" d="M15 4h10v16l10 20a5 5 0 0 1-4.4 8H9.4A5 5 0 0 1 5 40l10-20z"/>
          <path class="lb-fluid" d="M11 32h18l6 12a4 4 0 0 1-3.5 6H8.5A4 4 0 0 1 5 44z"/>
          <circle class="lb-bub b1" cx="15" cy="42" r="2"/>
          <circle class="lb-bub b2" cx="22" cy="45" r="1.5"/>
          <circle class="lb-bub b3" cx="27" cy="41" r="1.8"/>
          <line class="lb-glass" x1="13" y1="4" x2="27" y2="4"/>
        </svg>
        <div><b id="lb-n1">0</b><span>experiments<br>completed</span></div>
      </div>
      <div class="lb-g">
        <div class="lb-dial"><i id="lb-needle"></i><span class="lb-dial-c"></span></div>
        <div><b id="lb-n2">0</b><span>bandit level<br>reached</span></div>
      </div>
      <div class="lb-g">
        <div class="lb-tube"><i id="lb-fill"></i></div>
        <div><b id="lb-n3">0</b><span>platforms<br>active</span></div>
      </div>
    </div>
  </header>

  <div class="lb-filters" id="lb-filters"></div>

  <div class="lb-bench" id="lb-bench"></div>

  <footer class="lb-foot">
    <span class="lb-hz2"></span>
    <p>New experiments logged as they complete. Every writeup includes the method, not just the result.</p>
  </footer>

</div>

<style>
.lb{
  --base:#06080D; --surf:#0B1119; --line:rgba(255,255,255,.09);
  --violet:#7C5CFF; --mint:#00F0B5; --amber:#FFB020; --rose:#FF4D6D;
  --steel:#8A97AB; --ice:#DCE4F0;
  --d:'Chakra Petch',system-ui,sans-serif;
  --m:'IBM Plex Mono',ui-monospace,monospace;
  position:relative;font-family:var(--d);color:var(--ice);
  margin:-1.5rem -1rem 0;padding:clamp(24px,4vw,40px) 20px clamp(40px,6vw,70px);
  background:var(--base);overflow:hidden;min-height:76vh;
}
.lb *{box-sizing:border-box;margin:0;padding:0}
.lb>*:not(.lb-blue){position:relative;z-index:2}

/* blueprint */
.lb-blue{
  position:absolute;inset:0;pointer-events:none;z-index:0;
  background-image:
    linear-gradient(rgba(0,240,181,.05) 1px,transparent 1px),
    linear-gradient(90deg,rgba(0,240,181,.05) 1px,transparent 1px),
    linear-gradient(rgba(0,240,181,.028) 1px,transparent 1px),
    linear-gradient(90deg,rgba(0,240,181,.028) 1px,transparent 1px);
  background-size:96px 96px,96px 96px,19px 19px,19px 19px;
  mask-image:radial-gradient(ellipse 88% 68% at 50% 24%,#000 18%,transparent 86%);
  -webkit-mask-image:radial-gradient(ellipse 88% 68% at 50% 24%,#000 18%,transparent 86%);
}

/* hazard tape */
.lb-hz,.lb-hz2{
  display:block;height:5px;border-radius:2px;
  background:repeating-linear-gradient(45deg,var(--amber) 0 9px,#0B1119 9px 18px);
  opacity:.5;margin-bottom:20px;
}
.lb-hz2{margin:0 0 16px}

/* head */
.lb-head{padding-bottom:22px;border-bottom:1px solid var(--line);margin-bottom:clamp(20px,3.5vw,32px)}
.lb-head-in{margin-bottom:26px}
.lb-eye{font-family:var(--m);font-size:10px;letter-spacing:.24em;text-transform:uppercase;color:var(--mint);margin-bottom:10px!important}
.lb-title{font-weight:700;font-size:clamp(1.7rem,5.4vw,2.8rem);line-height:1.05;color:#fff;margin-bottom:11px!important}
.lb-sub{color:var(--steel);font-size:clamp(.86rem,1.6vw,.98rem);line-height:1.68;max-width:560px}

/* gauges */
.lb-gauges{display:grid;grid-template-columns:repeat(auto-fit,minmax(168px,1fr));gap:10px}
.lb-g{
  display:flex;align-items:center;gap:14px;
  border:1px solid var(--line);border-radius:11px;
  background:var(--surf);padding:14px 15px;
}
.lb-g b{display:block;font-family:var(--m);font-size:1.5rem;font-weight:600;color:var(--mint);line-height:1}
.lb-g span{display:block;font-family:var(--m);font-size:8.5px;letter-spacing:.13em;text-transform:uppercase;color:var(--steel);margin-top:6px;line-height:1.5}

/* flask */
.lb-flask{width:34px;height:44px;flex-shrink:0;overflow:visible}
.lb-glass{fill:none;stroke:var(--steel);stroke-width:2;stroke-linejoin:round;stroke-linecap:round;opacity:.75}
.lb-fluid{fill:var(--mint);opacity:.32}
.lb-bub{fill:var(--mint);opacity:.85}
.b1{animation:lbBub 2.4s ease-in infinite}
.b2{animation:lbBub 2.9s ease-in .5s infinite}
.b3{animation:lbBub 2.1s ease-in 1.1s infinite}
@keyframes lbBub{0%{transform:translateY(0);opacity:0}18%{opacity:.85}100%{transform:translateY(-15px);opacity:0}}

/* dial */
.lb-dial{
  width:36px;height:36px;border-radius:50%;flex-shrink:0;position:relative;
  border:2px solid rgba(255,255,255,.14);
  background:conic-gradient(from 180deg,var(--mint) 0deg,var(--amber) 120deg,var(--rose) 180deg,transparent 180deg,transparent 360deg);
}
.lb-dial::after{content:'';position:absolute;inset:4px;border-radius:50%;background:var(--surf)}
.lb-dial i{
  position:absolute;left:50%;bottom:50%;width:2px;height:12px;
  background:var(--ice);transform-origin:bottom center;z-index:2;border-radius:1px;
  transform:translateX(-50%) rotate(-90deg);
  transition:transform 1.6s cubic-bezier(.2,1.4,.4,1);
}
.lb-dial-c{position:absolute;left:50%;bottom:50%;width:5px;height:5px;border-radius:50%;background:var(--ice);transform:translate(-50%,50%);z-index:3}

/* tube */
.lb-tube{
  width:15px;height:38px;flex-shrink:0;border-radius:8px;
  border:2px solid rgba(255,255,255,.16);overflow:hidden;
  display:flex;align-items:flex-end;background:rgba(255,255,255,.03);
}
.lb-tube i{display:block;width:100%;height:0;background:linear-gradient(180deg,var(--violet),var(--mint));transition:height 1.4s cubic-bezier(.2,.9,.3,1)}

/* filters */
.lb-filters{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:18px}
.lb-f{
  font-family:var(--m);font-size:10px;letter-spacing:.12em;text-transform:uppercase;
  padding:7px 14px;border-radius:20px;cursor:pointer;
  background:transparent;border:1px solid var(--line);color:var(--steel);
  transition:all .18s;
}
.lb-f:hover{color:var(--ice);border-color:rgba(0,240,181,.4)}
.lb-f.on{color:var(--mint);border-color:var(--mint);background:rgba(0,240,181,.09)}

/* bench */
.lb-bench{display:grid;grid-template-columns:repeat(auto-fit,minmax(290px,1fr));gap:12px}
.lb-x{
  position:relative;border:1px solid var(--line);border-radius:12px;
  background:var(--surf);padding:17px;overflow:hidden;
  transition:border-color .22s,transform .22s;
  text-decoration:none;color:inherit;display:block;
}
.lb-x::before{
  content:'';position:absolute;inset:0;opacity:0;transition:opacity .22s;pointer-events:none;
  background:radial-gradient(circle at 50% 0%,rgba(0,240,181,.11),transparent 62%);
}
.lb-x:hover{border-color:rgba(0,240,181,.45);transform:translateY(-3px)}
.lb-x:hover::before{opacity:1}
.lb-x>*{position:relative;z-index:2}
.lb-x.done::after{
  content:'';position:absolute;top:0;left:0;width:100%;height:2px;
  background:linear-gradient(90deg,var(--mint),transparent);
}
.lb-x.wip::after{
  content:'';position:absolute;top:0;left:0;width:100%;height:2px;
  background:linear-gradient(90deg,var(--amber),transparent);
}

.lb-xh{display:flex;align-items:flex-start;gap:11px;margin-bottom:11px}
.lb-xn{
  font-family:var(--m);font-size:10px;letter-spacing:.1em;
  color:var(--mint);opacity:.75;flex-shrink:0;padding-top:2px;
}
.lb-xt{flex:1}
.lb-xt h3{font-size:.98rem;font-weight:600;color:#fff;line-height:1.3;margin-bottom:4px!important}
.lb-plat{font-family:var(--m);font-size:9px;letter-spacing:.14em;text-transform:uppercase;color:var(--steel)}
.lb-stat{
  font-family:var(--m);font-size:8.5px;font-weight:600;letter-spacing:.11em;
  padding:3px 8px;border-radius:4px;flex-shrink:0;
}
.st-done{background:rgba(0,240,181,.14);color:var(--mint)}
.st-wip{background:rgba(255,176,32,.14);color:var(--amber)}

.lb-xd{font-size:.83rem;line-height:1.62;color:var(--steel);margin-bottom:13px!important}
.lb-spec{display:flex;flex-wrap:wrap;gap:4px}
.lb-spec span{
  font-family:var(--m);font-size:8.5px;padding:3px 8px;border-radius:4px;
  background:rgba(124,92,255,.1);border:1px solid rgba(124,92,255,.2);color:var(--steel);
}
.lb-read{
  display:flex;align-items:center;gap:6px;margin-top:13px;
  font-family:var(--m);font-size:9.5px;letter-spacing:.14em;text-transform:uppercase;
  color:var(--mint);opacity:0;transform:translateX(-5px);transition:all .22s;
}
.lb-x:hover .lb-read{opacity:1;transform:none}

.lb-foot{margin-top:clamp(30px,5vw,52px)}
.lb-foot p{font-family:var(--m);font-size:10px;color:var(--steel);opacity:.6;line-height:1.65}

@media(prefers-reduced-motion:reduce){
  .lb-bub{animation:none}
  .lb-dial i,.lb-tube i{transition:none}
}
</style>

<script>
(function(){
var L=document.querySelector('.lb'); if(!L) return;
var slow=window.matchMedia('(prefers-reduced-motion: reduce)').matches;

var EXP=[
 {n:'001',t:'Brutus',plat:'HTB Sherlocks',k:'dfir',status:'done',
  d:'Rebuilt a full Linux compromise timeline from two log files. Brute force at 06:31, root at 06:31:40, backdoor account by 06:34, persistence script pulled by 06:39.',
  s:['auth.log','wtmp','brute force','T1136.001','MITRE'],
  u:'/posts/htb-sherlock-brutus-dfir-writeup/'},
 {n:'002',t:'Redeemer',plat:'HTB Starting Point',k:'recon',status:'done',
  d:'Unauthenticated Redis on port 6379, completely invisible to the default nmap scan. Connect, enumerate keys, read. No exploit required.',
  s:['redis','nmap -p-','misconfiguration','enumeration'],
  u:'/posts/htb-redeemer-redis-writeup/'},
 {n:'003',t:'Cap',plat:'HTB Starting Point',k:'exploit',status:'done',
  d:'Four weak links in one chain. IDOR exposed a PCAP, the PCAP held plaintext FTP credentials, password reuse gave SSH, and cap_setuid on Python 3.8 gave root.',
  s:['IDOR','pcap','ftp','linux capabilities','privesc'],
  u:'/posts/htb-cap-writeup/'},
 {n:'004',t:'Bandit',plat:'OverTheWire',k:'linux',status:'wip',
  d:'Working through SSH key authentication, file permission traps, and privilege escalation. Currently sitting at levels 17 to 18.',
  s:['bash','ssh','file permissions','privesc'],
  u:''},
 {n:'005',t:'Defensive scenarios',plat:'Blue Team Labs Online',k:'dfir',status:'wip',
  d:'Real world incident investigation exercises. Log analysis, phishing triage, and malware behaviour under a working analyst workflow.',
  s:['blue team','log analysis','incident response'],
  u:''},
 {n:'006',t:'Detection engineering',plat:'Home lab',k:'detect',status:'wip',
  d:'Building detection rules mapped to MITRE ATT&CK techniques and testing them against generated telemetry. Writeups follow as rules stabilise.',
  s:['MITRE ATT&CK','sigma','SIEM','wazuh'],
  u:''}
];

var FILTERS=[['all','all'],['dfir','forensics'],['exploit','exploitation'],['recon','recon'],['linux','linux'],['detect','detection']];
var cur='all';

var fh=document.getElementById('lb-filters');
fh.innerHTML=FILTERS.map(function(f,i){
  return '<button class="lb-f'+(i===0?' on':'')+'" data-f="'+f[0]+'">'+f[1]+'</button>';
}).join('');

function paint(){
  var list=EXP.filter(function(e){return cur==='all'||e.k===cur});
  document.getElementById('lb-bench').innerHTML=list.map(function(e){
    var tag=e.u?'a':'div', href=e.u?' href="'+e.u+'"':'';
    return '<'+tag+' class="lb-x '+e.status+'"'+href+'>'+
      '<div class="lb-xh">'+
        '<span class="lb-xn">EXP-'+e.n+'</span>'+
        '<div class="lb-xt"><h3>'+e.t+'</h3><span class="lb-plat">'+e.plat+'</span></div>'+
        '<span class="lb-stat st-'+(e.status==='done'?'done':'wip')+'">'+(e.status==='done'?'COMPLETE':'RUNNING')+'</span>'+
      '</div>'+
      '<p class="lb-xd">'+e.d+'</p>'+
      '<div class="lb-spec">'+e.s.map(function(x){return '<span>'+x+'</span>'}).join('')+'</div>'+
      (e.u?'<div class="lb-read">read the writeup \u2192</div>':'')+
    '</'+tag+'>';
  }).join('');
}
paint();

fh.addEventListener('click',function(ev){
  var b=ev.target.closest('.lb-f'); if(!b) return;
  fh.querySelectorAll('.lb-f').forEach(function(x){x.classList.remove('on')});
  b.classList.add('on'); cur=b.dataset.f; paint();
});

/* gauges */
function countTo(el,to){
  if(slow){el.textContent=to;return}
  var c=0,st=Math.max(1,Math.round(to/22));
  var iv=setInterval(function(){c+=st;if(c>=to){c=to;clearInterval(iv)}el.textContent=c},38);
}
function boot(){
  countTo(document.getElementById('lb-n1'),3);
  countTo(document.getElementById('lb-n2'),18);
  countTo(document.getElementById('lb-n3'),3);
  var nd=document.getElementById('lb-needle');
  if(nd) setTimeout(function(){ nd.style.transform='translateX(-50%) rotate(18deg)' },260);
  var fl=document.getElementById('lb-fill');
  if(fl) setTimeout(function(){ fl.style.height='62%' },200);
}
if('IntersectionObserver' in window){
  var io=new IntersectionObserver(function(es){
    if(es[0].isIntersecting){boot();io.disconnect()}
  },{threshold:.2});
  io.observe(document.querySelector('.lb-gauges'));
} else boot();

})();
</script>
