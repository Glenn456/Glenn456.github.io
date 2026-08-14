---
layout: page
title: Categories
icon: fas fa-database
order: 1
permalink: /categories/
---

<link href="https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">

<div class="ls">
  <div class="ls-bg"></div>

  <header class="ls-top">
    <div>
      <p class="ls-eye">// data sources</p>
      <h1 class="ls-h1">Log Sources</h1>
      <p class="ls-sub">Every category is a source feeding this site. Volume, last ingest, and status for each. Select a source to expand its event list.</p>
    </div>
    <div class="ls-stats" id="ls-stats"></div>
  </header>

  <div class="ls-ctl">
    <div class="ls-sort" id="ls-sort">
      <button class="ls-s on" data-s="vol">by volume</button>
      <button class="ls-s" data-s="recent">by last ingest</button>
      <button class="ls-s" data-s="name">alphabetical</button>
    </div>
    <span class="ls-live"><i></i>all sources reporting</span>
  </div>

  <div class="ls-grid" id="ls-grid"></div>
</div>

<style>
.ls{
  --base:#06080D; --surf:#0B1119; --line:rgba(255,255,255,.09);
  --violet:#7C5CFF; --mint:#00F0B5; --amber:#FFB020; --rose:#FF4D6D;
  --steel:#8A97AB; --ice:#DCE4F0;
  --d:'Chakra Petch',system-ui,sans-serif;
  --m:'IBM Plex Mono',ui-monospace,monospace;
  position:relative;font-family:var(--d);color:var(--ice);
  margin:-1.5rem -1rem 0;padding:clamp(24px,4vw,40px) 20px clamp(46px,6vw,74px);
  background:var(--base);overflow:hidden;min-height:76vh;
}
.ls *{box-sizing:border-box;margin:0;padding:0}
.ls>*:not(.ls-bg){position:relative;z-index:2}
.ls-bg{
  position:absolute;inset:0;z-index:0;pointer-events:none;
  background-image:
    linear-gradient(rgba(124,92,255,.05) 1px,transparent 1px),
    linear-gradient(90deg,rgba(124,92,255,.05) 1px,transparent 1px);
  background-size:40px 40px;
  mask-image:radial-gradient(ellipse 92% 62% at 50% 16%,#000 16%,transparent 84%);
  -webkit-mask-image:radial-gradient(ellipse 92% 62% at 50% 16%,#000 16%,transparent 84%);
}

.ls-top{display:flex;justify-content:space-between;align-items:flex-end;gap:22px;flex-wrap:wrap;
  padding-bottom:20px;border-bottom:1px solid var(--line);margin-bottom:18px}
.ls-eye{font-family:var(--m);font-size:10px;letter-spacing:.24em;text-transform:uppercase;color:var(--violet);margin-bottom:9px!important}
.ls-h1{font-weight:700;font-size:clamp(1.6rem,4.8vw,2.5rem);line-height:1.06;color:#fff;margin-bottom:10px!important}
.ls-sub{color:var(--steel);font-size:clamp(.84rem,1.6vw,.95rem);line-height:1.66;max-width:490px}
.ls-stats{display:flex;gap:20px;flex-wrap:wrap}
.ls-stats div b{display:block;font-family:var(--m);font-size:1.4rem;font-weight:600;color:var(--mint);line-height:1}
.ls-stats div span{display:block;font-family:var(--m);font-size:8.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--steel);margin-top:6px}

.ls-ctl{display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:16px}
.ls-sort{display:flex;gap:5px;flex-wrap:wrap}
.ls-s{
  font-family:var(--m);font-size:10px;letter-spacing:.1em;text-transform:uppercase;
  padding:6px 13px;border-radius:20px;cursor:pointer;
  background:transparent;border:1px solid var(--line);color:var(--steel);transition:all .18s;
}
.ls-s:hover{color:var(--ice)}
.ls-s.on{color:var(--violet);border-color:var(--violet);background:rgba(124,92,255,.09)}
.ls-live{font-family:var(--m);font-size:9px;letter-spacing:.14em;text-transform:uppercase;color:var(--steel);display:flex;align-items:center;gap:7px}
.ls-live i{width:5px;height:5px;border-radius:50%;background:var(--mint);animation:lsBeat 2.4s ease-in-out infinite}
@keyframes lsBeat{0%,100%{box-shadow:0 0 0 0 rgba(0,240,181,.55)}50%{box-shadow:0 0 0 6px rgba(0,240,181,0)}}

.ls-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:11px;align-items:start}

.ls-src{
  border:1px solid var(--line);border-radius:12px;background:var(--surf);
  overflow:hidden;transition:border-color .22s;
}
.ls-src:hover{border-color:rgba(124,92,255,.4)}
.ls-src.op{border-color:rgba(124,92,255,.55)}
.ls-hd{padding:15px 16px;cursor:pointer;position:relative}
.ls-hd-t{display:flex;align-items:center;gap:9px;margin-bottom:11px}
.ls-led{width:7px;height:7px;border-radius:50%;flex-shrink:0;animation:lsBeat 2.6s ease-in-out infinite}
.ls-nm{font-family:var(--m);font-size:12px;letter-spacing:.09em;text-transform:uppercase;color:var(--ice);flex:1;line-height:1.3}
.ls-ct{font-family:var(--m);font-size:10.5px;color:var(--mint);flex-shrink:0}
.ls-car{font-family:var(--m);font-size:11px;color:var(--steel);opacity:.5;transition:transform .24s;flex-shrink:0}
.ls-src.op .ls-car{transform:rotate(90deg);color:var(--violet);opacity:1}

.ls-vol{height:4px;border-radius:3px;background:rgba(255,255,255,.06);overflow:hidden;margin-bottom:9px}
.ls-vol i{display:block;height:100%;width:0;border-radius:3px;transition:width .9s cubic-bezier(.2,.85,.3,1)}
.v1 i{background:linear-gradient(90deg,var(--rose),var(--amber))}
.v2 i{background:linear-gradient(90deg,var(--amber),var(--violet))}
.v3 i{background:linear-gradient(90deg,var(--violet),rgba(124,92,255,.4))}
.ls-meta{display:flex;justify-content:space-between;font-family:var(--m);font-size:8.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--steel);opacity:.7}

.ls-body{max-height:0;overflow:hidden;transition:max-height .34s ease;border-top:0 solid var(--line)}
.ls-src.op .ls-body{max-height:1400px;border-top-width:1px}
.ls-ev{
  display:flex;gap:11px;align-items:flex-start;
  padding:9px 16px;text-decoration:none;
  border-bottom:1px solid rgba(255,255,255,.035);transition:background .15s;
}
.ls-ev:last-child{border-bottom:none}
.ls-ev:hover{background:rgba(124,92,255,.08)}
.ls-ed{font-family:var(--m);font-size:9px;color:var(--steel);opacity:.7;flex-shrink:0;padding-top:2px;min-width:56px}
.ls-et{font-family:var(--m);font-size:10.5px;line-height:1.5;color:var(--steel);transition:color .15s}
.ls-ev:hover .ls-et{color:var(--violet)}

.ls-fade{opacity:0;transform:translateY(14px)}
.ls-fade.up{opacity:1;transform:none;transition:opacity .5s ease,transform .5s ease}

@media(prefers-reduced-motion:reduce){
  .ls-led,.ls-live i{animation:none}
  .ls-vol i,.ls-body{transition:none}
  .ls-fade{opacity:1;transform:none}
}
</style>

<script>
(function(){
var SRC = [
{% for cat in site.categories %}
  { n: {{ cat[0] | jsonify }},
    p: [{% for post in cat[1] %}{ t: {{ post.title | jsonify }}, u: {{ post.url | jsonify }}, d: {{ post.date | date: "%Y-%m-%d" | jsonify }} }{% unless forloop.last %},{% endunless %}{% endfor %}]
  }{% unless forloop.last %},{% endunless %}
{% endfor %}
];

var root=document.querySelector('.ls'); if(!root) return;
var slow=window.matchMedia('(prefers-reduced-motion: reduce)').matches;

SRC.forEach(function(s){
  s.c = s.p.length;
  s.p.sort(function(a,b){ return a.d < b.d ? 1 : -1 });
  s.last = s.p.length ? s.p[0].d : '';
});

var maxC = SRC.reduce(function(m,s){ return Math.max(m,s.c) }, 1);
var totalEv = SRC.reduce(function(m,s){ return m + s.c }, 0);
var latest = SRC.reduce(function(m,s){ return s.last > m ? s.last : m }, '');

document.getElementById('ls-stats').innerHTML =
  '<div><b id="n1">0</b><span>sources</span></div>' +
  '<div><b id="n2">0</b><span>events</span></div>' +
  '<div><b style="font-size:.95rem">' + (latest||'--') + '</b><span>last ingest</span></div>';

function countTo(id,to){
  var el=document.getElementById(id); if(!el) return;
  if(slow){el.textContent=to;return}
  var c=0, st=Math.max(1,Math.round(to/22));
  var iv=setInterval(function(){c+=st;if(c>=to){c=to;clearInterval(iv)}el.textContent=c},36);
}
countTo('n1',SRC.length); countTo('n2',totalEv);

var sortMode='vol';
function render(){
  var list=SRC.slice();
  if(sortMode==='vol') list.sort(function(a,b){return b.c-a.c});
  else if(sortMode==='recent') list.sort(function(a,b){return a.last<b.last?1:-1});
  else list.sort(function(a,b){return a.n.toLowerCase()<b.n.toLowerCase()?-1:1});

  document.getElementById('ls-grid').innerHTML = list.map(function(s,i){
    var pct=Math.max(7,Math.round(s.c/maxC*100));
    var band = pct>66?'v1':(pct>33?'v2':'v3');
    var led  = pct>66?'var(--rose)':(pct>33?'var(--amber)':'var(--mint)');
    return '<div class="ls-src ls-fade">'+
      '<div class="ls-hd">'+
        '<div class="ls-hd-t">'+
          '<span class="ls-led" style="background:'+led+'"></span>'+
          '<span class="ls-nm">'+s.n+'</span>'+
          '<span class="ls-ct">'+s.c+'</span>'+
          '<span class="ls-car">&#9656;</span>'+
        '</div>'+
        '<div class="ls-vol '+band+'"><i data-w="'+pct+'"></i></div>'+
        '<div class="ls-meta"><span>last ingest '+(s.last||'--')+'</span><span>'+pct+'% of peak</span></div>'+
      '</div>'+
      '<div class="ls-body">'+ s.p.map(function(p){
          return '<a class="ls-ev" href="'+p.u+'"><span class="ls-ed">'+p.d.slice(5)+'</span><span class="ls-et">'+p.t+'</span></a>';
        }).join('') +'</div>'+
    '</div>';
  }).join('');

  var cards=root.querySelectorAll('.ls-src');
  cards.forEach(function(el,i){
    setTimeout(function(){
      el.classList.add('up');
      var bar=el.querySelector('.ls-vol i');
      if(bar) bar.style.width=bar.dataset.w+'%';
    }, slow?0:60+i*55);
    el.querySelector('.ls-hd').addEventListener('click',function(){ el.classList.toggle('op') });
  });
}
render();

document.getElementById('ls-sort').addEventListener('click',function(e){
  var b=e.target.closest('.ls-s'); if(!b) return;
  root.querySelectorAll('.ls-s').forEach(function(x){x.classList.remove('on')});
  b.classList.add('on'); sortMode=b.dataset.s; render();
});
})();
</script>
