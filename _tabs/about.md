---
layout: page
title: About
icon: fas fa-user
order: 5
permalink: /about/
---

<link href="https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">

<div class="sg">

<!-- ═════════ HERO ═════════ -->
<section class="sg-hero">
  <canvas id="sg-noise"></canvas>
  <div class="sg-scan" id="sg-scan"></div>
  <div class="sg-vig"></div>

  <div class="sg-hero-in">
    <p class="sg-kicker">
      <span class="sg-blip"></span>Nairobi &nbsp;/&nbsp; <span id="sg-clock">--:--:--</span> EAT
    </p>

    <h1 class="sg-name" data-txt="ONGALO GLENN">ONGALO GLENN</h1>
    <p class="sg-role" data-txt="SECURITY ANALYST">SECURITY ANALYST</p>

    <p class="sg-tag">
      I find the signal in the noise. Move your cursor across this page to see what I mean.
    </p>

    <div class="sg-readout">
      <div><b data-n="42">0</b><span>articles</span></div>
      <div><b data-n="3">0</b><span>boxes rooted</span></div>
      <div><b data-n="18">0</b><span>bandit level</span></div>
      <div><b data-n="7">0</b><span>weeks on audit</span></div>
    </div>

    <div class="sg-cue"><span></span>scroll</div>
  </div>
</section>

<!-- ═════════ LIVE ALERT ═════════ -->
<section class="sg-sec">
  <p class="sg-eye">// live detection</p>
  <h2 class="sg-h2">An alert just fired</h2>
  <p class="sg-lead">You landed on this page. Here is what that looks like from the other side of a console. Everything below was read from your browser, in your browser. None of it was sent anywhere, and I have no idea who you are.</p>

  <div class="sg-alert" id="sg-alert">
    <div class="sg-alert-bar">
      <span class="sg-sev">LOW</span>
      <span class="sg-rule">RULE-0042 · Unfamiliar visitor observed</span>
      <span class="sg-ts" id="sg-alert-ts">--:--:--</span>
    </div>
    <div class="sg-fields" id="sg-fields"></div>
    <div class="sg-verdict">
      <span class="sg-vk">verdict</span>
      <span class="sg-vv" id="sg-verdict">analysing...</span>
    </div>
  </div>
</section>

<!-- ═════════ WHO ═════════ -->
<section class="sg-sec">
  <p class="sg-eye">// summary</p>
  <h2 class="sg-h2">Who is behind the console</h2>
  <p class="sg-body">I run IT infrastructure and cyber risk consulting at <b>Digi Africa</b>, working with betting and gaming operators on cyber insurance risk, <b>AML and CTF compliance</b>, and incident response for fiduciary data leaks. I graduated top of my class from <b>Cyber Shujaa</b>, and I recently spent seven weeks on an IT audit engagement testing whether client control environments actually hold up under evidence.</p>
  <p class="sg-body">The thing I am actually good at is the part before the tooling: working out what a pile of logs is telling you, and what question to ask next. Everything on this site is the working record of that. Every lab, every incident, every breakdown of an attack that was in the news last week.</p>
  <p class="sg-body">I am looking for a <b>SOC analyst</b> role on a team that treats detection as engineering rather than shopping.</p>
</section>

<!-- ═════════ LOG ═════════ -->
<section class="sg-sec">
  <p class="sg-eye">// event log</p>
  <h2 class="sg-h2">Track record</h2>
  <p class="sg-hint">Tap any line to expand it.</p>
  <div class="sg-log" id="sg-log"></div>
</section>

<!-- ═════════ CAPABILITY ═════════ -->
<section class="sg-sec">
  <p class="sg-eye">// capability</p>
  <h2 class="sg-h2">What I actually operate</h2>
  <p class="sg-hint">Weighted by hours spent, not courses watched.</p>
  <div class="sg-grid" id="sg-grid"></div>
</section>

<!-- ═════════ CTA ═════════ -->
<section class="sg-cta">
  <h2 class="sg-h2">Let us talk</h2>
  <p class="sg-body">Nairobi based, open to remote. I answer every message, including the ones that turn into a no.</p>
  <div class="sg-btns">
    <a class="sg-b sg-b1" href="mailto:ongaloglenn45@gmail.com">ongaloglenn45@gmail.com</a>
    <a class="sg-b sg-b2" href="tel:+254745530525">+254 745 530 525</a>
    <a class="sg-b" href="/labs/">Lab writeups</a>
    <a class="sg-b" href="/archives/">All writing</a>
  </div>
</section>

</div>

<style>
.sg{
  --base:#06080D; --surf:#0C1119; --line:rgba(255,255,255,.09);
  --violet:#7C5CFF; --mint:#00F0B5; --rose:#FF4D6D;
  --steel:#8A97AB; --ice:#DCE4F0;
  --d:'Chakra Petch',system-ui,sans-serif;
  --m:'IBM Plex Mono',ui-monospace,monospace;
  font-family:var(--d);
  margin:-1.5rem -1rem 0;
  background:var(--base);
  color:var(--ice);
  overflow-x:clip;
}
.sg *{box-sizing:border-box;margin:0;padding:0}

/* ── HERO ── */
.sg-hero{
  position:relative;min-height:min(88vh,760px);
  display:flex;align-items:center;justify-content:center;
  padding:clamp(50px,9vw,90px) 22px;overflow:hidden;
  border-bottom:1px solid var(--line);
}
#sg-noise{position:absolute;inset:0;width:100%;height:100%;display:block}
.sg-scan{
  position:absolute;width:340px;height:340px;border-radius:50%;
  pointer-events:none;opacity:0;transition:opacity .4s;
  background:radial-gradient(circle,rgba(124,92,255,.22) 0%,rgba(124,92,255,.07) 42%,transparent 68%);
  mix-blend-mode:screen;
}
.sg-vig{
  position:absolute;inset:0;pointer-events:none;
  background:radial-gradient(ellipse 74% 62% at 50% 46%,transparent 0%,rgba(6,8,13,.82) 72%,var(--base) 100%);
}
.sg-hero-in{position:relative;z-index:3;text-align:center;max-width:820px}

.sg-kicker{
  font-family:var(--m);font-size:11px;letter-spacing:.24em;
  color:var(--steel);text-transform:uppercase;margin-bottom:22px!important;
  display:flex;align-items:center;justify-content:center;gap:9px;
}
.sg-blip{
  width:7px;height:7px;border-radius:50%;background:var(--mint);
  animation:sgBlip 2.2s ease-in-out infinite;
}
@keyframes sgBlip{0%,100%{box-shadow:0 0 0 0 rgba(0,240,181,.55)}50%{box-shadow:0 0 0 8px rgba(0,240,181,0)}}

.sg-name{
  font-weight:700;letter-spacing:.01em;line-height:.95;
  font-size:clamp(2.4rem,9vw,6rem);
  color:#fff;margin-bottom:10px!important;
}
.sg-role{
  font-family:var(--m);font-weight:500;
  font-size:clamp(.72rem,2.1vw,1.15rem);
  letter-spacing:.42em;color:var(--violet);
  margin-bottom:26px!important;
}
.sg-tag{
  color:var(--steel);line-height:1.68;max-width:470px;margin:0 auto 34px!important;
  font-size:clamp(.9rem,1.7vw,1.06rem);
}

.sg-readout{
  display:grid;grid-template-columns:repeat(4,1fr);gap:1px;
  background:var(--line);border:1px solid var(--line);border-radius:12px;
  overflow:hidden;max-width:560px;margin:0 auto;
}
.sg-readout div{background:rgba(12,17,25,.78);padding:15px 8px;backdrop-filter:blur(6px)}
.sg-readout b{
  display:block;font-family:var(--m);font-weight:600;
  font-size:clamp(1.2rem,3.4vw,1.7rem);color:var(--mint);line-height:1;
}
.sg-readout span{
  display:block;font-family:var(--m);font-size:9px;letter-spacing:.16em;
  text-transform:uppercase;color:var(--steel);margin-top:7px;
}

.sg-cue{
  margin-top:38px;font-family:var(--m);font-size:9.5px;
  letter-spacing:.3em;text-transform:uppercase;color:var(--steel);opacity:.55;
}
.sg-cue span{
  display:block;width:1px;height:26px;margin:0 auto 9px;
  background:linear-gradient(var(--violet),transparent);
  animation:sgDrop 2s ease-in-out infinite;
}
@keyframes sgDrop{0%,100%{opacity:.25;transform:scaleY(.6)}50%{opacity:1;transform:scaleY(1)}}

/* ── SECTIONS ── */
.sg-sec{padding:clamp(52px,8vw,92px) 22px;max-width:900px;margin:0 auto;border-bottom:1px solid var(--line)}
.sg-eye{
  font-family:var(--m);font-size:10.5px;letter-spacing:.24em;
  color:var(--violet);text-transform:uppercase;margin-bottom:14px!important;
}
.sg-h2{
  font-weight:600;font-size:clamp(1.5rem,4.4vw,2.5rem);
  line-height:1.14;color:#fff;margin-bottom:18px!important;letter-spacing:-.01em;
}
.sg-lead{color:var(--steel);line-height:1.72;font-size:clamp(.9rem,1.7vw,1.02rem);margin-bottom:26px!important;max-width:640px}
.sg-body{color:var(--steel);line-height:1.78;font-size:clamp(.9rem,1.7vw,1.02rem);margin-bottom:16px!important;max-width:680px}
.sg-body b{color:var(--ice);font-weight:600}
.sg-hint{font-family:var(--m);font-size:11px;color:var(--steel);opacity:.55;margin-bottom:20px!important}

/* ── ALERT ── */
.sg-alert{border:1px solid var(--line);border-radius:12px;overflow:hidden;background:var(--surf)}
.sg-alert-bar{
  display:flex;align-items:center;gap:12px;flex-wrap:wrap;
  padding:12px 16px;background:rgba(124,92,255,.09);
  border-bottom:1px solid var(--line);
}
.sg-sev{
  font-family:var(--m);font-size:9.5px;font-weight:600;letter-spacing:.16em;
  padding:3px 9px;border-radius:4px;
  background:rgba(0,240,181,.14);color:var(--mint);
}
.sg-rule{font-family:var(--m);font-size:11.5px;color:var(--ice);flex:1;min-width:180px}
.sg-ts{font-family:var(--m);font-size:11px;color:var(--steel)}

.sg-fields{padding:6px 0}
.sg-f{
  display:flex;gap:14px;padding:9px 16px;
  font-family:var(--m);font-size:11.5px;line-height:1.5;
  border-bottom:1px solid rgba(255,255,255,.04);
  opacity:0;transform:translateX(-8px);
  transition:opacity .3s,transform .3s;
}
.sg-f.in{opacity:1;transform:none}
.sg-f:last-child{border-bottom:none}
.sg-fk{color:var(--steel);min-width:118px;flex-shrink:0}
.sg-fv{color:var(--mint);word-break:break-word}

.sg-verdict{
  display:flex;gap:14px;align-items:baseline;flex-wrap:wrap;
  padding:15px 16px;border-top:1px solid var(--line);
  background:rgba(124,92,255,.06);
}
.sg-vk{font-family:var(--m);font-size:9.5px;letter-spacing:.2em;text-transform:uppercase;color:var(--steel)}
.sg-vv{font-family:var(--m);font-size:12.5px;color:var(--violet);flex:1;min-width:200px;line-height:1.55}

/* ── LOG ── */
.sg-log{border-top:1px solid var(--line)}
.sg-row{border-bottom:1px solid var(--line);cursor:pointer;transition:background .2s}
.sg-row:hover{background:rgba(124,92,255,.05)}
.sg-rt{display:flex;align-items:center;gap:13px;padding:15px 4px}
.sg-date{font-family:var(--m);font-size:10.5px;color:var(--steel);min-width:58px;flex-shrink:0}
.sg-tag2{
  font-family:var(--m);font-size:9px;font-weight:600;letter-spacing:.1em;
  padding:3px 8px;border-radius:4px;flex-shrink:0;
}
.t-role{background:rgba(124,92,255,.16);color:#A48DFF}
.t-lab{background:rgba(0,240,181,.14);color:var(--mint)}
.t-cert{background:rgba(255,77,109,.14);color:#FF8098}
.sg-what{flex:1;font-size:.92rem;font-weight:500;line-height:1.34;color:var(--ice)}
.sg-where{display:block;font-family:var(--m);font-size:10.5px;color:var(--steel);margin-top:3px;font-weight:400}
.sg-car{font-family:var(--m);font-size:12px;color:var(--steel);opacity:.5;transition:transform .25s}
.sg-row.op .sg-car{transform:rotate(90deg);color:var(--violet);opacity:1}
.sg-det{max-height:0;overflow:hidden;transition:max-height .34s ease}
.sg-row.op .sg-det{max-height:520px}
.sg-di{padding:0 4px 20px 71px;color:var(--steel);font-size:.87rem;line-height:1.72}
.sg-di ul{list-style:none}
.sg-di li{padding:4px 0 4px 18px;position:relative}
.sg-di li::before{content:'';position:absolute;left:0;top:13px;width:7px;height:1px;background:var(--violet)}
.sg-di code{font-family:var(--m);font-size:.9em;color:var(--mint);background:rgba(0,240,181,.08);padding:1px 5px;border-radius:3px}
@media(max-width:560px){.sg-di{padding-left:4px}}

/* ── GRID ── */
.sg-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(152px,1fr));gap:9px}
.sg-cat{border:1px solid var(--line);border-radius:10px;padding:14px;background:var(--surf)}
.sg-ch{
  font-family:var(--m);font-size:9px;letter-spacing:.18em;text-transform:uppercase;
  color:var(--steel);margin-bottom:11px;
}
.sg-sk{
  font-size:.79rem;padding:6px 10px;border-radius:6px;margin-bottom:5px;
  border-left:2px solid;transition:transform .18s,background .18s;
}
.sg-sk:last-child{margin-bottom:0}
.sg-sk:hover{transform:translateX(4px)}
.w3{background:rgba(124,92,255,.15);border-left-color:var(--violet);color:var(--ice)}
.w2{background:rgba(124,92,255,.07);border-left-color:rgba(124,92,255,.45);color:var(--steel)}
.w1{background:rgba(255,255,255,.03);border-left-color:rgba(255,255,255,.14);color:var(--steel)}

/* ── CTA ── */
.sg-cta{padding:clamp(56px,9vw,100px) 22px;max-width:900px;margin:0 auto;text-align:center}
.sg-cta .sg-body{margin-left:auto;margin-right:auto}
.sg-btns{display:flex;gap:10px;flex-wrap:wrap;justify-content:center;margin-top:26px}
.sg-b{
  font-family:var(--m);font-size:11.5px;letter-spacing:.05em;
  padding:12px 22px;border-radius:8px;text-decoration:none;
  border:1px solid var(--line);color:var(--steel)!important;
  transition:all .2s;
}
.sg-b:hover{border-color:var(--violet);color:var(--ice)!important}
.sg-b1{background:var(--violet);border-color:var(--violet);color:#fff!important;font-weight:600}
.sg-b2{border-color:rgba(0,240,181,.45);color:var(--mint)!important}
.sg-b2:hover{background:rgba(0,240,181,.12);border-color:var(--mint);color:var(--mint)!important}
.sg-b1:hover{background:#8E72FF;border-color:#8E72FF;color:#fff!important}

/* ── reveal ── */
.sg-up{opacity:0;transform:translateY(20px);transition:opacity .6s,transform .6s}
.sg-up.in{opacity:1;transform:none}

@media(max-width:640px){
  .sg-readout{grid-template-columns:repeat(2,1fr)}
  .sg-scan{display:none}
}
@media(prefers-reduced-motion:reduce){
  .sg-up{opacity:1;transform:none;transition:none}
  .sg-blip,.sg-cue span{animation:none}
  .sg-f{opacity:1;transform:none}
}
</style>

<script>
(function(){
var root=document.querySelector('.sg'); if(!root) return;
var slow=window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/* ══ CLOCK ══ */
function clk(){
  var d=new Date(new Date().toLocaleString('en-US',{timeZone:'Africa/Nairobi'}));
  var p=function(n){return String(n).padStart(2,'0')};
  var s=p(d.getHours())+':'+p(d.getMinutes())+':'+p(d.getSeconds());
  var a=document.getElementById('sg-clock'); if(a)a.textContent=s;
}
clk(); setInterval(clk,1000);

/* ══ HEX NOISE CANVAS ══ */
var cv=document.getElementById('sg-noise');
if(cv){
  var cx=cv.getContext('2d'), W,H, cols,rows, CW=13, CH=17, grid=[], raf, vis=true;
  var GLY='0123456789ABCDEF';
  function size(){
    var r=cv.parentElement.getBoundingClientRect();
    var dpr=Math.min(window.devicePixelRatio||1,2);
    W=r.width; H=r.height;
    cv.width=W*dpr; cv.height=H*dpr;
    cx.setTransform(dpr,0,0,dpr,0,0);
    cols=Math.ceil(W/CW); rows=Math.ceil(H/CH);
    grid=[];
    for(var y=0;y<rows;y++){
      var line=[];
      for(var x=0;x<cols;x++) line.push({c:GLY[(Math.random()*16)|0],a:.05+Math.random()*.13,t:Math.random()*260|0});
      grid.push(line);
    }
  }
  var mx=-9999,my=-9999;
  function draw(){
    if(!vis){raf=requestAnimationFrame(draw);return}
    cx.clearRect(0,0,W,H);
    cx.font='12px "IBM Plex Mono",monospace';
    cx.textBaseline='top';
    for(var y=0;y<rows;y++){
      for(var x=0;x<cols;x++){
        var g=grid[y][x];
        if(--g.t<0){g.c=GLY[(Math.random()*16)|0];g.t=180+((Math.random()*260)|0)}
        var px=x*CW, py=y*CH;
        var dx=px-mx, dy=py-my;
        var d2=dx*dx+dy*dy;
        if(d2<28900){
          var f=1-Math.sqrt(d2)/170;
          cx.fillStyle='rgba(124,92,255,'+(g.a+f*.78)+')';
        } else {
          cx.fillStyle='rgba(138,151,171,'+g.a+')';
        }
        cx.fillText(g.c,px,py);
      }
    }
    raf=requestAnimationFrame(draw);
  }
  size();
  if(!slow) draw(); else { cx.font='12px monospace'; }
  window.addEventListener('resize',size,{passive:true});

  var sc=document.getElementById('sg-scan');
  root.querySelector('.sg-hero').addEventListener('mousemove',function(e){
    var r=cv.getBoundingClientRect();
    mx=e.clientX-r.left; my=e.clientY-r.top;
    if(sc){sc.style.opacity='1';sc.style.left=(mx-170)+'px';sc.style.top=(my-170)+'px'}
  },{passive:true});
  root.querySelector('.sg-hero').addEventListener('mouseleave',function(){
    mx=-9999;my=-9999;
    if(sc)sc.style.opacity='0';
  },{passive:true});

  if('IntersectionObserver' in window){
    new IntersectionObserver(function(es){vis=es[0].isIntersecting},{threshold:0}).observe(cv);
  }
}

/* ══ DECRYPT HEADINGS ══ */
var CH='!<>-_\\/[]{}=+*^?#01ABCDEF';
function decrypt(el){
  var final=el.dataset.txt||el.textContent, n=final.length, f=0;
  var q=[];
  for(var i=0;i<n;i++){
    q.push({c:final[i],s:Math.floor(Math.random()*18),e:Math.floor(Math.random()*18)+18});
  }
  (function step(){
    var out='',done=0;
    for(var i=0;i<n;i++){
      var o=q[i];
      if(f>=o.e){done++;out+=o.c}
      else if(f>=o.s){out+= o.c===' '?' ':CH[(Math.random()*CH.length)|0]}
      else out+= o.c===' '?' ':CH[(Math.random()*CH.length)|0];
    }
    el.textContent=out;
    if(done<n){f++;requestAnimationFrame(step)}
    else el.textContent=final;
  })();
}

/* ══ VISITOR ALERT ══ */
function buildAlert(){
  var f=[];
  var now=new Date();
  var p=function(n){return String(n).padStart(2,'0')};
  var ts=document.getElementById('sg-alert-ts');
  if(ts) ts.textContent=p(now.getHours())+':'+p(now.getMinutes())+':'+p(now.getSeconds());

  var tz='unknown';
  try{tz=Intl.DateTimeFormat().resolvedOptions().timeZone||'unknown'}catch(e){}

  var ua=navigator.userAgent||'';
  var br = /Edg\//.test(ua)?'Edge' : /OPR\//.test(ua)?'Opera' :
           /Firefox\//.test(ua)?'Firefox' : /Chrome\//.test(ua)?'Chrome' :
           /Safari\//.test(ua)?'Safari':'unidentified';
  var os = /Android/.test(ua)?'Android' : /iPhone|iPad|iPod/.test(ua)?'iOS' :
           /Mac OS X/.test(ua)?'macOS' : /Windows/.test(ua)?'Windows' :
           /Linux/.test(ua)?'Linux':'unidentified';
  var mob=/Mobi|Android|iPhone/.test(ua);
  var dark=window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches;
  var ref=document.referrer;
  var refHost='direct / bookmark';
  if(ref){ try{refHost=new URL(ref).hostname}catch(e){refHost='external'} }

  f.push(['session.start', p(now.getHours())+':'+p(now.getMinutes())+':'+p(now.getSeconds())+' local']);
  f.push(['src.timezone', tz]);
  f.push(['device.type', mob?'mobile handset':'desktop or laptop']);
  f.push(['user.agent', br+' on '+os]);
  f.push(['display.res', (window.screen?screen.width+' x '+screen.height:'n/a')+' @ '+(window.devicePixelRatio||1)+'x']);
  f.push(['locale', (navigator.language||'n/a')+(navigator.languages&&navigator.languages.length>1?' (+'+(navigator.languages.length-1)+' more)':'')]);
  f.push(['ui.theme', dark?'dark mode':'light mode']);
  f.push(['referrer', refHost]);
  f.push(['cpu.threads', (navigator.hardwareConcurrency||'not disclosed')+'']);
  f.push(['data.exfiltrated', 'none — this never left your device']);

  var host=document.getElementById('sg-fields');
  if(!host) return;
  host.innerHTML=f.map(function(x){
    return '<div class="sg-f"><span class="sg-fk">'+x[0]+'</span><span class="sg-fv">'+x[1]+'</span></div>';
  }).join('');

  var rows=host.querySelectorAll('.sg-f');
  rows.forEach(function(r,i){ setTimeout(function(){r.classList.add('in')}, slow?0:i*95); });

  /* verdict */
  var v;
  var hour=now.getHours();
  if(tz.indexOf('Nairobi')>-1) v='Same timezone as me. If you are hiring in Nairobi, we should talk.';
  else if(hour>=23||hour<5) v='Reading a stranger\u0027s about page after midnight. Respect. Benign, whitelisting.';
  else if(refHost.indexOf('linkedin')>-1) v='Arrived from LinkedIn. Almost certainly a recruiter. Escalating to inbox.';
  else if(refHost.indexOf('github')>-1) v='Came in from GitHub. Probably an engineer. Try the labs page.';
  else if(refHost.indexOf('google')>-1) v='Organic search. Something I wrote answered a question you had. Good.';
  else if(mob) v='Mobile visitor, likely between other things. Everything here scales down fine.';
  else v='Benign. Curious human, non-adversarial. No action required beyond saying hello.';

  var vv=document.getElementById('sg-verdict');
  if(vv){
    if(slow){vv.textContent=v;return}
    setTimeout(function(){
      var i=0; vv.textContent='';
      (function t(){ vv.textContent=v.slice(0,++i); if(i<v.length) setTimeout(t,17); })();
    }, rows.length*95+250);
  }
}

/* ══ LOG ══ */
var LOG=[
  {d:'2026-08',k:'cert',t:'AUDIT',w:'IT audit engagement, seven weeks',o:'cyber risk management firm',
   h:'<ul><li>Design and operating effectiveness testing across access management, change management, backup and recovery, and third-party governance</li><li>Evidence-based sampling across a review period rather than point-in-time checks</li><li>Findings written with defensible risk ratings and agreed management responses</li><li>The most useful thing it taught me: an unevidenced control is an untested control</li></ul>'},
  {d:'2026-06',k:'lab',t:'LAB',w:'HTB Cap, rooted',o:'hack the box',
   h:'IDOR on a dashboard exposed a PCAP holding plaintext FTP credentials. Password reuse gave SSH. A <code>cap_setuid</code> capability on Python 3.8 gave root. Four weak links, one chain.'},
  {d:'2026-06',k:'lab',t:'DFIR',w:'HTB Sherlock: Brutus',o:'hack the box',
   h:'Rebuilt a full Linux compromise timeline from <code>auth.log</code> and <code>wtmp</code>. Brute force through to a backdoor account and a persistence script pull. Mapped to <code>T1136.001</code>.'},
  {d:'2026-06',k:'lab',t:'LAB',w:'HTB Redeemer, rooted',o:'hack the box',
   h:'Unauthenticated Redis on 6379, invisible to the default nmap scan. The lesson that actually stuck: always run <code>-p-</code>.'},
  {d:'2026-03',k:'role',t:'ROLE',w:'Head of IT Infrastructure and Innovation',o:'digi africa, subsidiary of mga group',
   h:'<ul><li>Lead infrastructure strategy and day to day security operations</li><li>Cyber insurance risk consulting for betting and gaming operators</li><li>AML and CTF compliance, including suspicious pattern identification</li><li>Incident response for fiduciary data leaks, investigation through to reporting</li></ul>'},
  {d:'2026-02',k:'cert',t:'CERT',w:'Cyber Shujaa, Security Analyst track',o:'graduated top of class',
   h:'Network security, application security, cloud security, incident response, security architecture, IoT security, and digital forensics. Competitive national selection.'},
  {d:'2024-11',k:'role',t:'ROLE',w:'Research Analyst',o:'mga group',
   h:'<ul><li>Investigated complex datasets for patterns, anomalies, and risk indicators</li><li>Built statistical models in Python and R for risk scoring</li><li>Produced structured risk and compliance reporting for senior stakeholders</li></ul>'},
  {d:'2023-12',k:'cert',t:'EDU',w:'BSc Business Information Technology',o:'jkuat',
   h:'Systems analysis, databases, networking, and business process design. The analytics foundation everything else was built on.'}
];
var lg=document.getElementById('sg-log');
if(lg){
  lg.innerHTML=LOG.map(function(e){
    return '<div class="sg-row"><div class="sg-rt">'+
      '<span class="sg-date">'+e.d+'</span>'+
      '<span class="sg-tag2 t-'+e.k+'">'+e.t+'</span>'+
      '<span class="sg-what">'+e.w+'<span class="sg-where">'+e.o+'</span></span>'+
      '<span class="sg-car">&#9656;</span></div>'+
      '<div class="sg-det"><div class="sg-di">'+e.h+'</div></div></div>';
  }).join('');
  lg.addEventListener('click',function(ev){
    var r=ev.target.closest('.sg-row'); if(r) r.classList.toggle('op');
  });
}

/* ══ GRID ══ */
var CAP=[
 {h:'detect & respond',s:[['Log analysis',3],['Alert triage',3],['Incident response',3],['DFIR',2],['Threat hunting',2],['Splunk / Wazuh',2]]},
 {h:'risk & compliance',s:[['AML / CTF',3],['Cyber insurance risk',3],['IT audit & controls',3],['Third-party risk',2],['Data Protection Act',2]]},
 {h:'networks',s:[['TCP/IP & DNS',3],['Packet analysis',2],['Nmap & enumeration',2],['Wireshark',2]]},
 {h:'systems',s:[['Linux',2],['Windows event logs',2],['Entra ID / IAM',2],['Cloud logging',2]]},
 {h:'frameworks',s:[['MITRE ATT&CK',3],['Cyber Kill Chain',3],['Zero Trust',2],['NIST CSF',1]]},
 {h:'code & data',s:[['Python',3],['SQL',2],['R',2],['Bash',2],['Power BI',3]]}
];
var gd=document.getElementById('sg-grid');
if(gd){
  gd.innerHTML=CAP.map(function(c){
    return '<div class="sg-cat"><div class="sg-ch">'+c.h+'</div>'+
      c.s.map(function(s){return '<div class="sg-sk w'+s[1]+'">'+s[0]+'</div>'}).join('')+'</div>';
  }).join('');
}

/* ══ OBSERVERS ══ */
var counted=false, alerted=false, decrypted=false;
function countUp(el){
  var to=+el.dataset.n,c=0,st=Math.max(1,Math.round(to/26));
  if(slow){el.textContent=to;return}
  var iv=setInterval(function(){c+=st;if(c>=to){c=to;clearInterval(iv)}el.textContent=c},34);
}
if('IntersectionObserver' in window){
  var io=new IntersectionObserver(function(es){
    es.forEach(function(e){
      if(!e.isIntersecting) return;
      if(e.target.classList.contains('sg-hero') && !counted){
        counted=true;
        root.querySelectorAll('.sg-readout b').forEach(countUp);
      }
      if(e.target.id==='sg-alert' && !alerted){ alerted=true; buildAlert(); }
      e.target.classList.add('in');
      io.unobserve(e.target);
    });
  },{threshold:.15});
  var hero=root.querySelector('.sg-hero'); if(hero) io.observe(hero);
  var al=document.getElementById('sg-alert'); if(al) io.observe(al);
} else {
  root.querySelectorAll('.sg-readout b').forEach(function(x){x.textContent=x.dataset.n});
  buildAlert();
}

/* boot decrypt */
if(!slow){
  setTimeout(function(){
    var n=root.querySelector('.sg-name'), r=root.querySelector('.sg-role');
    if(n) decrypt(n);
    if(r) setTimeout(function(){decrypt(r)},260);
  },180);
}
})();
</script>
