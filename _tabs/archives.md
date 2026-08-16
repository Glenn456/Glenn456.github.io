---
layout: page
title: Archives
icon: fas fa-clock-rotate-left
order: 4
permalink: /archives/
---

<link href="https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">

<div class="eh">
  <div class="eh-bg"></div>

  <header class="eh-top">
    <div>
      <p class="eh-eye">// historical search</p>
      <h1 class="eh-h1">Event History</h1>
      <p class="eh-sub">Everything published, oldest retained event to the most recent. Drag across the density chart or pick a window below.</p>
    </div>
    <div class="eh-stats" id="eh-stats"></div>
  </header>

  <section class="eh-chart-wrap">
    <div class="eh-ch-h">
      <span>event density by month</span>
      <span class="eh-peak" id="eh-peak"></span>
    </div>
    <div class="eh-chart" id="eh-chart"></div>
    <div class="eh-axis" id="eh-axis"></div>
    <div class="eh-tip" id="eh-tip"></div>
  </section>

  <div class="eh-ctl" id="eh-ctl"></div>

  <div class="eh-log" id="eh-log"></div>
</div>

<style>
.eh{
  --base:#06080D; --surf:#0B1119; --line:rgba(255,255,255,.09);
  --violet:#7C5CFF; --mint:#00F0B5; --amber:#FFB020; --rose:#FF4D6D;
  --steel:#8A97AB; --ice:#DCE4F0;
  --d:'Chakra Petch',system-ui,sans-serif;
  --m:'IBM Plex Mono',ui-monospace,monospace;
  position:relative;font-family:var(--d);color:var(--ice);
  margin:-1.5rem -1rem 0;padding:clamp(24px,4vw,40px) 20px clamp(46px,6vw,74px);
  background:var(--base);overflow:hidden;min-height:76vh;
}
.eh *{box-sizing:border-box;margin:0;padding:0}
.eh>*:not(.eh-bg){position:relative;z-index:2}
.eh-bg{
  position:absolute;inset:0;z-index:0;pointer-events:none;
  background-image:
    linear-gradient(rgba(124,92,255,.05) 1px,transparent 1px),
    linear-gradient(90deg,rgba(124,92,255,.05) 1px,transparent 1px);
  background-size:40px 40px;
  mask-image:radial-gradient(ellipse 92% 60% at 50% 14%,#000 14%,transparent 84%);
  -webkit-mask-image:radial-gradient(ellipse 92% 60% at 50% 14%,#000 14%,transparent 84%);
}

.eh-top{display:flex;justify-content:space-between;align-items:flex-end;gap:22px;flex-wrap:wrap;
  padding-bottom:20px;border-bottom:1px solid var(--line);margin-bottom:20px}
.eh-eye{font-family:var(--m);font-size:10px;letter-spacing:.24em;text-transform:uppercase;color:var(--violet);margin-bottom:9px!important}
.eh-h1{font-weight:700;font-size:clamp(1.6rem,4.8vw,2.5rem);line-height:1.06;color:#fff;margin-bottom:10px!important}
.eh-sub{color:var(--steel);font-size:clamp(.84rem,1.6vw,.95rem);line-height:1.66;max-width:470px}
.eh-stats{display:flex;gap:20px;flex-wrap:wrap}
.eh-stats div b{display:block;font-family:var(--m);font-size:1.35rem;font-weight:600;color:var(--mint);line-height:1}
.eh-stats div span{display:block;font-family:var(--m);font-size:8.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--steel);margin-top:6px}

/* histogram */
.eh-chart-wrap{
  border:1px solid var(--line);border-radius:12px;background:var(--surf);
  padding:14px 16px 11px;margin-bottom:18px;position:relative;
}
.eh-ch-h{display:flex;justify-content:space-between;font-family:var(--m);font-size:8.5px;
  letter-spacing:.16em;text-transform:uppercase;color:var(--steel);margin-bottom:12px}
.eh-peak{color:var(--mint)}
.eh-chart{display:flex;align-items:flex-end;gap:3px;height:96px}
.eh-b{
  flex:1;min-width:5px;border-radius:2px 2px 0 0;height:0;
  background:linear-gradient(180deg,var(--violet),rgba(124,92,255,.22));
  cursor:pointer;position:relative;
  transition:height .8s cubic-bezier(.2,.85,.3,1),background .18s,filter .18s;
}
.eh-b.hi{background:linear-gradient(180deg,var(--rose),rgba(255,77,109,.25))}
.eh-b.md{background:linear-gradient(180deg,var(--amber),rgba(255,176,32,.25))}
.eh-b:hover{filter:brightness(1.5)}
.eh-b.sel{outline:1px solid var(--mint);outline-offset:1px}
.eh-axis{display:flex;gap:3px;margin-top:7px;font-family:var(--m);font-size:7.5px;color:var(--steel);opacity:.55}
.eh-axis span{flex:1;min-width:5px;text-align:center;overflow:hidden;white-space:nowrap}
.eh-tip{
  position:absolute;pointer-events:none;opacity:0;transition:opacity .15s;
  background:#000;border:1px solid rgba(124,92,255,.5);border-radius:6px;
  padding:5px 9px;font-family:var(--m);font-size:9.5px;color:var(--ice);
  white-space:nowrap;transform:translate(-50%,-118%);z-index:9;
}
.eh-tip.on{opacity:1}

/* window filter */
.eh-ctl{display:flex;gap:5px;flex-wrap:wrap;margin-bottom:16px;align-items:center}
.eh-w{
  font-family:var(--m);font-size:10px;letter-spacing:.1em;text-transform:uppercase;
  padding:6px 13px;border-radius:20px;cursor:pointer;
  background:transparent;border:1px solid var(--line);color:var(--steel);transition:all .18s;
}
.eh-w:hover{color:var(--ice)}
.eh-w.on{color:var(--mint);border-color:var(--mint);background:rgba(0,240,181,.08)}
.eh-count{font-family:var(--m);font-size:9px;letter-spacing:.14em;text-transform:uppercase;color:var(--steel);margin-left:auto}

/* log */
.eh-log{border-top:1px solid var(--line)}
.eh-yr{
  display:flex;align-items:center;gap:10px;
  font-family:var(--m);font-size:10px;letter-spacing:.24em;text-transform:uppercase;
  color:var(--violet);padding:20px 0 9px;
}
.eh-yr::after{content:'';flex:1;height:1px;background:linear-gradient(90deg,rgba(124,92,255,.4),transparent)}
.eh-r{
  display:flex;align-items:flex-start;gap:13px;
  padding:10px 8px 10px 0;text-decoration:none;
  border-bottom:1px solid rgba(255,255,255,.04);
  position:relative;transition:background .15s,padding-left .18s;
}
.eh-r:hover{background:rgba(124,92,255,.06);padding-left:6px}
.eh-r::before{
  content:'';position:absolute;left:-8px;top:0;bottom:0;width:2px;
  background:var(--mint);transform:scaleY(0);transition:transform .2s;
}
.eh-r:hover::before{transform:scaleY(.65)}
.eh-ts{font-family:var(--m);font-size:9.5px;color:var(--steel);opacity:.75;flex-shrink:0;min-width:62px;padding-top:2px;letter-spacing:.04em}
.eh-cat{
  font-family:var(--m);font-size:8px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;
  padding:3px 7px;border-radius:4px;flex-shrink:0;margin-top:1px;
  background:rgba(124,92,255,.13);color:#A48DFF;
}
.eh-t{font-family:var(--m);font-size:11px;line-height:1.55;color:var(--steel);transition:color .15s;flex:1}
.eh-r:hover .eh-t{color:var(--ice)}
.eh-t.dec{color:var(--violet);text-shadow:0 0 8px rgba(124,92,255,.45)}

@media(max-width:600px){
  .eh-axis{display:none}
  .eh-cat{display:none}
}
@media(prefers-reduced-motion:reduce){
  .eh-b{transition:none}
}
</style>

<script>
(function(){
var POSTS = [
{% for post in site.posts %}
  { t: {{ post.title | jsonify }},
    u: {{ post.url | jsonify }},
    d: {{ post.date | date: "%Y-%m-%d" | jsonify }},
    c: {{ post.categories.first | default: "General" | jsonify }} }{% unless forloop.last %},{% endunless %}
{% endfor %}
];

var root=document.querySelector('.eh'); if(!root||!POSTS.length) return;
var slow=window.matchMedia('(prefers-reduced-motion: reduce)').matches;
var MON=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

POSTS.sort(function(a,b){return a.d<b.d?1:-1});
var newest=POSTS[0].d, oldest=POSTS[POSTS.length-1].d;

document.getElementById('eh-stats').innerHTML=
  '<div><b id="e1">0</b><span>events</span></div>'+
  '<div><b style="font-size:.92rem">'+oldest+'</b><span>oldest retained</span></div>'+
  '<div><b style="font-size:.92rem">'+newest+'</b><span>most recent</span></div>';

(function(){
  var el=document.getElementById('e1'), to=POSTS.length;
  if(slow){el.textContent=to;return}
  var c=0,st=Math.max(1,Math.round(to/24));
  var iv=setInterval(function(){c+=st;if(c>=to){c=to;clearInterval(iv)}el.textContent=c},34);
})();

/* ---- month buckets ---- */
function ym(d){return d.slice(0,7)}
var buckets={}, order=[];
var s=oldest.slice(0,7), e=newest.slice(0,7);
var y=+s.slice(0,4), m=+s.slice(5,7);
while(true){
  var key=y+'-'+String(m).padStart(2,'0');
  buckets[key]=[]; order.push(key);
  if(key===e) break;
  m++; if(m>12){m=1;y++}
  if(order.length>240) break;
}
POSTS.forEach(function(p){ var k=ym(p.d); if(buckets[k]) buckets[k].push(p); });
var peak=Math.max.apply(null,order.map(function(k){return buckets[k].length}));
document.getElementById('eh-peak').textContent='peak '+peak+' / month';

var chart=document.getElementById('eh-chart'), axis=document.getElementById('eh-axis'), tip=document.getElementById('eh-tip');
chart.innerHTML=order.map(function(k){
  var n=buckets[k].length, pct=peak?Math.round(n/peak*100):0;
  var cls = pct>66?'hi':(pct>33?'md':'');
  return '<div class="eh-b '+cls+'" data-k="'+k+'" data-h="'+Math.max(n?8:2,pct)+'" title=""></div>';
}).join('');
axis.innerHTML=order.map(function(k,i){
  var mm=+k.slice(5,7);
  return '<span>'+((order.length<=14||i%2===0)?MON[mm-1]:'')+'</span>';
}).join('');

setTimeout(function(){
  chart.querySelectorAll('.eh-b').forEach(function(b,i){
    setTimeout(function(){ b.style.height=b.dataset.h+'%' }, slow?0:i*32);
  });
},120);

chart.addEventListener('mousemove',function(ev){
  var b=ev.target.closest('.eh-b'); if(!b){tip.classList.remove('on');return}
  var k=b.dataset.k, n=buckets[k].length;
  tip.textContent=MON[+k.slice(5,7)-1]+' '+k.slice(0,4)+' \u00b7 '+n+' event'+(n===1?'':'s');
  var r=b.getBoundingClientRect(), w=chart.getBoundingClientRect();
  tip.style.left=(r.left-w.left+r.width/2)+'px';
  tip.style.top=(r.top-w.top)+'px';
  tip.classList.add('on');
});
chart.addEventListener('mouseleave',function(){tip.classList.remove('on')});

/* ---- window filter ---- */
var years=[]; order.forEach(function(k){var yy=k.slice(0,4); if(years.indexOf(yy)<0)years.push(yy)});
var win='all', selMonth=null;
var ctl=document.getElementById('eh-ctl');
ctl.innerHTML='<button class="eh-w on" data-w="all">full retention</button>'+
  years.map(function(yy){return '<button class="eh-w" data-w="'+yy+'">'+yy+'</button>'}).join('')+
  '<span class="eh-count" id="eh-count"></span>';

ctl.addEventListener('click',function(ev){
  var b=ev.target.closest('.eh-w'); if(!b) return;
  ctl.querySelectorAll('.eh-w').forEach(function(x){x.classList.remove('on')});
  b.classList.add('on'); win=b.dataset.w; selMonth=null;
  chart.querySelectorAll('.eh-b').forEach(function(x){x.classList.remove('sel')});
  paint();
});
chart.addEventListener('click',function(ev){
  var b=ev.target.closest('.eh-b'); if(!b) return;
  chart.querySelectorAll('.eh-b').forEach(function(x){x.classList.remove('sel')});
  if(selMonth===b.dataset.k){selMonth=null}
  else{selMonth=b.dataset.k; b.classList.add('sel')}
  paint();
});

/* ---- decrypt ---- */
var G='!<>-_\\/[]{}=+*^?#01ABCDEF';
function dec(el){
  var fin=el.dataset.fin||el.textContent; el.dataset.fin=fin;
  if(el._raf){ cancelAnimationFrame(el._raf); el._raf=0; }
  var n=fin.length,f=0,q=[];
  for(var i=0;i<n;i++)q.push({c:fin[i],e:((Math.random()*10)|0)+8});
  el.classList.add('dec');
  (function step(){
    var out='',done=0;
    for(var i=0;i<n;i++){var o=q[i];
      if(f>=o.e){done++;out+=o.c}
      else if(o.c===' '){out+=' '}
      else out+=G[(Math.random()*G.length)|0];
    }
    el.textContent=out;
    if(done<n){f++; el._raf=requestAnimationFrame(step)}
    else{el._raf=0; el.textContent=fin; el.classList.remove('dec')}
  })();
}

/* Fires every time a row scrolls into view, not just the first.
   Two thresholds: decode once past 45% visible, then re-arm only after the
   row has left the viewport completely, so hovering at the edge cannot loop. */
var dio = ('IntersectionObserver' in window) ? new IntersectionObserver(function(es){
  es.forEach(function(e){
    var el=e.target, r=e.intersectionRatio;
    if(r>=0.45){
      if(el._armed){ el._armed=false; dec(el); }
    } else if(r===0){
      el._armed=true;
    }
  });
},{threshold:[0,0.45]}) : null;

function paint(){
  var list=POSTS.filter(function(p){
    if(selMonth) return ym(p.d)===selMonth;
    if(win==='all') return true;
    return p.d.slice(0,4)===win;
  });
  document.getElementById('eh-count').textContent=list.length+' of '+POSTS.length+' events';

  var html='', curY='';
  list.forEach(function(p){
    var yy=p.d.slice(0,4);
    if(yy!==curY){curY=yy; html+='<div class="eh-yr">'+yy+'</div>'}
    html+='<a class="eh-r" href="'+p.u+'">'+
      '<span class="eh-ts">'+p.d.slice(5)+'</span>'+
      '<span class="eh-cat">'+p.c+'</span>'+
      '<span class="eh-t">'+p.t+'</span></a>';
  });
  document.getElementById('eh-log').innerHTML=html||'<p style="padding:24px 0;font-family:var(--m);font-size:11px;color:var(--steel)">no events in this window</p>';

  if(dio && !slow){
    dio.disconnect();
    root.querySelectorAll('.eh-t').forEach(function(el){
      el._armed = true;
      dio.observe(el);
    });
  }
}
paint();
})();
</script>
