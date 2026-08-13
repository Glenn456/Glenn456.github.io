---
layout: page
title: Games
icon: fas fa-gamepad
order: 3
permalink: /games/
---

<style>
.gm-intro {
  border-left: 3px solid var(--link-color);
  padding: 12px 16px;
  margin-bottom: 1.6rem;
  background: var(--card-bg);
  border-radius: 0 6px 6px 0;
}
.gm-intro p { margin: 6px 0 0; font-size: 0.88rem; opacity: 0.75; }

.gm-tabs { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 1.2rem; }
.gm-tab {
  font-size: 0.78rem; font-weight: 600; letter-spacing: 0.4px;
  padding: 7px 14px; border-radius: 20px; cursor: pointer;
  border: 1px solid var(--btn-border-color, #3a3a3f);
  background: transparent; color: inherit; opacity: 0.55;
  transition: all 0.2s;
}
.gm-tab:hover { opacity: 0.85; }
.gm-tab.on {
  opacity: 1; border-color: var(--link-color);
  color: var(--link-color); background: rgba(126,178,236,0.08);
}

.gm-panel { display: none; }
.gm-panel.on { display: block; }

.gm-card {
  background: var(--card-bg);
  border: 1px solid var(--btn-border-color, #3a3a3f);
  border-radius: 12px;
  padding: 20px;
  margin-bottom: 1rem;
}
.gm-head { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; margin-bottom: 14px; }
.gm-title { font-size: 1rem; font-weight: 700; margin: 0; }
.gm-sub { font-size: 0.8rem; opacity: 0.55; margin: 3px 0 0; }
.gm-score { font-size: 0.78rem; font-family: monospace; opacity: 0.7; white-space: nowrap; }
.gm-score b { color: var(--link-color); font-size: 0.95rem; }

.gm-btn {
  font-size: 0.82rem; font-weight: 600; padding: 9px 18px;
  border-radius: 7px; cursor: pointer; transition: all 0.18s;
  border: 1px solid var(--link-color); background: transparent; color: var(--link-color);
}
.gm-btn:hover { background: var(--link-color); color: #fff; }
.gm-btn:disabled { opacity: 0.35; cursor: not-allowed; }
.gm-btn.danger { border-color: #ff5f56; color: #ff5f56; }
.gm-btn.danger:hover { background: #ff5f56; color: #fff; }
.gm-btn.safe { border-color: #27c93f; color: #27c93f; }
.gm-btn.safe:hover { background: #27c93f; color: #fff; }
.gm-row { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 14px; }

.gm-msgbox {
  background: rgba(128,128,128,0.07);
  border: 1px solid var(--btn-border-color, #3a3a3f);
  border-radius: 8px; padding: 14px 16px; min-height: 130px;
}
.gm-msg-from { font-size: 0.75rem; opacity: 0.55; margin-bottom: 3px; font-family: monospace; }
.gm-msg-subj { font-size: 0.92rem; font-weight: 700; margin-bottom: 8px; }
.gm-msg-body { font-size: 0.87rem; line-height: 1.55; white-space: pre-wrap; }

.gm-feedback { margin-top: 12px; padding: 11px 14px; border-radius: 7px; font-size: 0.83rem; line-height: 1.5; display: none; }
.gm-feedback.right { display: block; background: rgba(39,201,63,0.1); border-left: 3px solid #27c93f; }
.gm-feedback.wrong { display: block; background: rgba(255,95,86,0.1); border-left: 3px solid #ff5f56; }

.gm-code {
  font-family: monospace; font-size: 0.95rem; letter-spacing: 1px;
  background: rgba(128,128,128,0.1); border-radius: 7px;
  padding: 14px 16px; word-break: break-all; text-align: center;
  border: 1px dashed var(--btn-border-color, #3a3a3f);
}
.gm-badge {
  display: inline-block; font-size: 0.68rem; font-weight: 700;
  letter-spacing: 1px; padding: 2px 9px; border-radius: 10px;
  background: rgba(126,178,236,0.15); color: var(--link-color);
  margin-bottom: 8px;
}
.gm-input {
  width: 100%; padding: 10px 13px; font-size: 0.9rem; font-family: monospace;
  border-radius: 7px; border: 1px solid var(--btn-border-color, #3a3a3f);
  background: rgba(128,128,128,0.06); color: inherit; outline: none;
}
.gm-input:focus { border-color: var(--link-color); }

.gm-meter { height: 9px; border-radius: 5px; background: rgba(128,128,128,0.18); overflow: hidden; margin: 12px 0 8px; }
.gm-meter-fill { height: 100%; width: 0%; transition: width 0.3s, background 0.3s; border-radius: 5px; }
.gm-checks { list-style: none; padding: 0; margin: 12px 0 0; font-size: 0.82rem; }
.gm-checks li { padding: 3px 0; opacity: 0.45; transition: opacity 0.2s; }
.gm-checks li.hit { opacity: 1; color: #27c93f; }
.gm-crack { font-family: monospace; font-size: 0.85rem; margin-top: 10px; opacity: 0.8; }

.gm-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; }
.gm-tile {
  aspect-ratio: 1; border-radius: 8px; cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  font-size: 0.7rem; font-weight: 700; text-align: center; padding: 4px;
  border: 1px solid var(--btn-border-color, #3a3a3f);
  background: rgba(128,128,128,0.08);
  transition: all 0.2s; user-select: none; line-height: 1.15;
}
.gm-tile .face { opacity: 0; transition: opacity 0.15s; }
.gm-tile.up { background: rgba(126,178,236,0.16); border-color: var(--link-color); }
.gm-tile.up .face { opacity: 1; }
.gm-tile.done { background: rgba(39,201,63,0.14); border-color: #27c93f; cursor: default; }
.gm-tile.done .face { opacity: 1; }
.gm-tile:not(.up):not(.done):hover { background: rgba(128,128,128,0.16); }
.gm-tile .q { font-size: 1.3rem; opacity: 0.25; }
.gm-tile.up .q, .gm-tile.done .q { display: none; }

@media(max-width:600px){ .gm-grid { grid-template-columns: repeat(4, 1fr); } .gm-tile { font-size: 0.58rem; } }
</style>

<div class="gm-intro">
  <strong>Four short games that teach real security concepts.</strong>
  <p>No sign-up, nothing stored on a server, all running in your browser. Built these because security ideas stick better when you have to actually make the call yourself.</p>
</div>

<div class="gm-tabs">
  <button class="gm-tab on" data-g="0">🎣 Phish or Legit</button>
  <button class="gm-tab" data-g="1">🔐 Cipher Cracker</button>
  <button class="gm-tab" data-g="2">🔑 Password Lab</button>
  <button class="gm-tab" data-g="3">🧠 Port Match</button>
</div>

<!-- ══════════ GAME 1: PHISH OR LEGIT ══════════ -->
<div class="gm-panel on" id="p0">
<div class="gm-card">
  <div class="gm-head">
    <div>
      <p class="gm-title">Phish or Legit</p>
      <p class="gm-sub">Real-world message patterns. Call it before the money moves.</p>
    </div>
    <div class="gm-score">Round <b id="f-round">1</b>/10 &nbsp;·&nbsp; Score <b id="f-score">0</b></div>
  </div>
  <div class="gm-msgbox">
    <div class="gm-badge" id="f-chan">SMS</div>
    <div class="gm-msg-from" id="f-from"></div>
    <div class="gm-msg-subj" id="f-subj"></div>
    <div class="gm-msg-body" id="f-body"></div>
  </div>
  <div class="gm-feedback" id="f-fb"></div>
  <div class="gm-row" id="f-controls">
    <button class="gm-btn danger" onclick="fAnswer(true)">🎣 Phishing</button>
    <button class="gm-btn safe" onclick="fAnswer(false)">✅ Legitimate</button>
  </div>
  <div class="gm-row" id="f-next" style="display:none">
    <button class="gm-btn" onclick="fNext()">Next →</button>
  </div>
</div>
</div>

<!-- ══════════ GAME 2: CIPHER CRACKER ══════════ -->
<div class="gm-panel" id="p1">
<div class="gm-card">
  <div class="gm-head">
    <div>
      <p class="gm-title">Cipher Cracker</p>
      <p class="gm-sub">Decode the intercepted payload. Encodings analysts see every week.</p>
    </div>
    <div class="gm-score">Level <b id="c-lvl">1</b>/8 &nbsp;·&nbsp; Score <b id="c-score">0</b></div>
  </div>
  <div class="gm-badge" id="c-type">BASE64</div>
  <div class="gm-code" id="c-code"></div>
  <div style="margin-top:14px">
    <input class="gm-input" id="c-in" placeholder="type the decoded text..." autocomplete="off" spellcheck="false">
  </div>
  <div class="gm-feedback" id="c-fb"></div>
  <div class="gm-row">
    <button class="gm-btn" onclick="cCheck()">Submit</button>
    <button class="gm-btn" onclick="cHint()">Hint (-20)</button>
  </div>
</div>
</div>

<!-- ══════════ GAME 3: PASSWORD LAB ══════════ -->
<div class="gm-panel" id="p2">
<div class="gm-card">
  <div class="gm-head">
    <div>
      <p class="gm-title">Password Lab</p>
      <p class="gm-sub">Watch entropy and crack time change as you type. Nothing leaves your browser.</p>
    </div>
    <div class="gm-score">Entropy <b id="w-bits">0</b> bits</div>
  </div>
  <input class="gm-input" id="w-in" placeholder="start typing a password..." autocomplete="off" spellcheck="false">
  <div class="gm-meter"><div class="gm-meter-fill" id="w-bar"></div></div>
  <div style="font-size:0.85rem;font-weight:700" id="w-label">Type something to begin</div>
  <div class="gm-crack" id="w-crack"></div>
  <ul class="gm-checks">
    <li id="w-c1">12 or more characters</li>
    <li id="w-c2">Mixed upper and lower case</li>
    <li id="w-c3">Contains numbers</li>
    <li id="w-c4">Contains symbols</li>
    <li id="w-c5">Not a common or predictable pattern</li>
  </ul>
  <div style="margin-top:16px;font-size:0.8rem;opacity:0.6;line-height:1.55">
    Crack time assumes an offline attack at 100 billion guesses per second against a fast hash. A slow hash like bcrypt or Argon2 makes this dramatically harder, which is exactly why the choice of hashing algorithm matters as much as the password itself.
  </div>
</div>
</div>

<!-- ══════════ GAME 4: PORT MATCH ══════════ -->
<div class="gm-panel" id="p3">
<div class="gm-card">
  <div class="gm-head">
    <div>
      <p class="gm-title">Port Match</p>
      <p class="gm-sub">Match each port to its service. Memory game for the ports you meet on every scan.</p>
    </div>
    <div class="gm-score">Moves <b id="m-moves">0</b> &nbsp;·&nbsp; Found <b id="m-found">0</b>/8</div>
  </div>
  <div class="gm-grid" id="m-grid"></div>
  <div class="gm-feedback" id="m-fb"></div>
  <div class="gm-row">
    <button class="gm-btn" onclick="mInit()">New Game</button>
  </div>
</div>
</div>

<script>
(function(){

/* ─── TABS ─────────────────────────────── */
document.querySelectorAll('.gm-tab').forEach(function(t){
  t.addEventListener('click', function(){
    document.querySelectorAll('.gm-tab').forEach(function(x){x.classList.remove('on');});
    document.querySelectorAll('.gm-panel').forEach(function(x){x.classList.remove('on');});
    t.classList.add('on');
    document.getElementById('p'+t.dataset.g).classList.add('on');
  });
});

/* ─── GAME 1: PHISH OR LEGIT ───────────── */
var FEED = [
  { chan:"SMS", from:"MPESA", subj:"", phish:false,
    body:"WK42XY9L1M Confirmed. Ksh2,500.00 sent to JOHN OMONDI 0712345678 on 8/8/26 at 3:14 PM. New M-PESA balance is Ksh8,420.00. Transaction cost, Ksh29.00.",
    why:"Legitimate. Real M-PESA confirmations come from the MPESA sender ID, contain a transaction code, and never contain a link or ask you to do anything." },
  { chan:"SMS", from:"+254 7XX XXX XXX", subj:"", phish:true,
    body:"Dear customer, your M-PESA account has been suspended due to unusual activity. To reactivate, reply with your ID number and M-PESA PIN within 2 hours or your account will be closed permanently.",
    why:"Phishing. Sent from a personal number, not a sender ID. No provider will ever ask for your PIN, and the deadline exists purely to stop you thinking." },
  { chan:"EMAIL", from:"security-alerts@equity-bank-ke.com", subj:"Unusual Sign-In Attempt Detected", phish:true,
    body:"We detected a sign-in from a new device in Lagos, Nigeria.\n\nIf this was not you, verify your identity immediately:\nhttps://equity-bank-ke.com/verify-account\n\nFailure to verify within 24 hours will result in account suspension.",
    why:"Phishing. The domain is a lookalike, not the bank's real domain. Legitimate alerts tell you to log in through the app or the official site, never through a link with a countdown attached." },
  { chan:"EMAIL", from:"noreply@github.com", subj:"[GitHub] A new SSH key was added to your account", phish:false,
    body:"A new SSH key was added to your account.\n\nKey fingerprint: SHA256:x9Kd...\n\nIf you did not add this key, please review your account security settings at github.com/settings/keys.",
    why:"Legitimate. Correct sender domain, factual notification, and it directs you to navigate to the settings page yourself rather than clicking a supplied link." },
  { chan:"SMS", from:"MPESA", subj:"", phish:true,
    body:"Confirmed. You have received Ksh15,000.00 from SAMUEL KIPTOO. New balance Ksh21,300.00.\n\n[2 min later, phone call] Hello, I sent money to the wrong number by mistake. Please reverse it, I have children to feed.",
    why:"Phishing, the reversal scam. The confirmation was spoofed and no money arrived. If you send Ksh15,000 back, you are sending your own funds. Always check your actual balance in the app before acting." },
  { chan:"EMAIL", from:"a.mwangi@yourcompany.co.ke", subj:"Urgent - Confidential Payment", phish:true,
    body:"I am in a board meeting and cannot take calls.\n\nI need you to process a payment of KES 1,450,000 to a new supplier today. Details attached. Please keep this confidential until the deal is announced.\n\nSent from my iPhone",
    why:"Phishing, CEO fraud. Urgency plus confidentiality plus a new beneficiary plus an excuse for why you cannot verify. That combination is the signature of business email compromise." },
  { chan:"EMAIL", from:"accounts@supplierltd.co.ke", subj:"Updated Banking Details - Invoice INV-8841", phish:true,
    body:"Dear Accounts Team,\n\nPlease note we have changed our banking provider. Kindly update your records and remit payment for INV-8841 to:\n\nBank: [New Bank]\nAccount: 01XXXXXXXXX\n\nApologies for any inconvenience.",
    why:"Phishing, vendor invoice fraud. The invoice may be real and the relationship genuine, but bank detail changes must always be verified by calling a number from your own vendor records, never a number in the email." },
  { chan:"SMS", from:"SAFARICOM", subj:"", phish:false,
    body:"Your Safaricom line 07XX XXX XXX has 1.2GB data remaining, expiring on 15/08/26. Dial *544# to top up.",
    why:"Legitimate. Registered sender ID, no link, no request for information, and it points you to a USSD code you dial yourself." },
  { chan:"EMAIL", from:"no-reply@microsoft-verify.net", subj:"Action Required: Verify your device", phish:true,
    body:"Your organisation requires device verification.\n\nGo to microsoft.com/devicelogin and enter code: XKCD-9931\n\nThis code expires in 15 minutes.",
    why:"Phishing, OAuth device code attack. The destination is the real Microsoft page and you will complete a real MFA challenge, but the token gets issued to the attacker who generated that code. Never enter a code you did not personally request." },
  { chan:"SMS", from:"KRA", subj:"", phish:true,
    body:"KRA NOTICE: You have an outstanding tax liability of KES 47,300. Pay via Paybill 8XXXXX Acc: your PIN within 48hrs to avoid penalties and legal action. Ignore if already paid.",
    why:"Phishing. KRA communicates tax obligations through iTax and formal notices, not SMS demands with a paybill number and a 48 hour threat. Always log in to iTax directly to check." }
];

var fi=0, fs=0, fAnswered=false;

function fRender(){
  var m=FEED[fi];
  document.getElementById('f-round').textContent=fi+1;
  document.getElementById('f-score').textContent=fs;
  document.getElementById('f-chan').textContent=m.chan;
  document.getElementById('f-from').textContent="From: "+m.from;
  document.getElementById('f-subj').textContent=m.subj||"";
  document.getElementById('f-subj').style.display=m.subj?"block":"none";
  document.getElementById('f-body').textContent=m.body;
  document.getElementById('f-fb').className='gm-feedback';
  document.getElementById('f-controls').style.display='flex';
  document.getElementById('f-next').style.display='none';
  fAnswered=false;
}

window.fAnswer=function(saidPhish){
  if(fAnswered) return;
  fAnswered=true;
  var m=FEED[fi], correct=(saidPhish===m.phish);
  if(correct) fs+=10;
  var fb=document.getElementById('f-fb');
  fb.className='gm-feedback '+(correct?'right':'wrong');
  fb.innerHTML='<strong>'+(correct?'Correct.':'Not quite.')+'</strong> '+m.why;
  document.getElementById('f-score').textContent=fs;
  document.getElementById('f-controls').style.display='none';
  document.getElementById('f-next').style.display='flex';
};

window.fNext=function(){
  fi++;
  if(fi>=FEED.length){
    var pct=Math.round((fs/(FEED.length*10))*100);
    var verdict = pct>=90?"Excellent. You would catch almost everything.":
                  pct>=70?"Solid. A few would still get through.":
                  pct>=50?"Mixed. Worth revisiting the ones you missed.":
                          "Worth a second run. These patterns are the ones costing people real money.";
    document.querySelector('#p0 .gm-msgbox').innerHTML=
      '<div style="text-align:center;padding:26px 10px">'+
      '<div style="font-size:2rem;font-weight:800;color:var(--link-color)">'+fs+' / '+(FEED.length*10)+'</div>'+
      '<div style="margin-top:8px;font-size:0.88rem;opacity:0.75">'+verdict+'</div></div>';
    document.getElementById('f-fb').className='gm-feedback';
    document.getElementById('f-next').innerHTML='<button class="gm-btn" onclick="fRestart()">Play Again</button>';
    return;
  }
  fRender();
};

window.fRestart=function(){
  fi=0; fs=0;
  document.querySelector('#p0 .gm-msgbox').innerHTML=
    '<div class="gm-badge" id="f-chan">SMS</div>'+
    '<div class="gm-msg-from" id="f-from"></div>'+
    '<div class="gm-msg-subj" id="f-subj"></div>'+
    '<div class="gm-msg-body" id="f-body"></div>';
  document.getElementById('f-next').innerHTML='<button class="gm-btn" onclick="fNext()">Next →</button>';
  fRender();
};

fRender();

/* ─── GAME 2: CIPHER CRACKER ───────────── */
var CIPH=[
  {t:"BASE64", c:"c29jYW5hbHlzdA==", a:["socanalyst"], h:"Base64 always decodes to plain text. Try atob('...') in your browser console."},
  {t:"ROT13", c:"CUVFUVAT", a:["phishing"], h:"ROT13 shifts each letter 13 places. C becomes P, U becomes H, V becomes I."},
  {t:"BINARY", c:"01001100 01001111 01000111 01010011", a:["logs"], h:"Each 8-bit group is one character. 01001100 is 76, which is L."},
  {t:"HEX", c:"6d616c776172 65".replace(" ",""), a:["malware"], h:"Convert each pair of hex digits to ASCII. 6d is 109, which is m."},
  {t:"BASE64", c:"emVybyB0cnVzdA==", a:["zero trust"], h:"Two words. Decodes to a security architecture principle."},
  {t:"ROT13", c:"ZNYJNER", a:["malware"], h:"Z becomes M, N becomes A, Y becomes L."},
  {t:"HEX", c:"6b656e7961", a:["kenya"], h:"Five characters. 6b is 107, which is k."},
  {t:"BINARY", c:"01001101 01000110 01000001", a:["mfa"], h:"Three characters. An authentication control."}
];
var ci=0, cs=0;

function cRender(){
  var l=CIPH[ci];
  document.getElementById('c-lvl').textContent=ci+1;
  document.getElementById('c-score').textContent=cs;
  document.getElementById('c-type').textContent=l.t;
  document.getElementById('c-code').textContent=l.c;
  document.getElementById('c-in').value='';
  document.getElementById('c-fb').className='gm-feedback';
}

window.cCheck=function(){
  var v=document.getElementById('c-in').value.trim().toLowerCase();
  if(!v) return;
  var l=CIPH[ci], fb=document.getElementById('c-fb');
  if(l.a.some(function(x){return v===x;})){
    cs+=50;
    ci++;
    if(ci>=CIPH.length){
      fb.className='gm-feedback right';
      fb.innerHTML='<strong>All levels cleared.</strong> Final score: '+cs+' points. These four encodings cover most of what turns up in obfuscated payloads and C2 traffic.';
      document.getElementById('c-code').textContent='✓ COMPLETE';
      document.getElementById('c-in').disabled=true;
      document.getElementById('c-score').textContent=cs;
      return;
    }
    cRender();
    fb.className='gm-feedback right';
    fb.innerHTML='<strong>Correct.</strong> Next payload loaded.';
  } else {
    cs=Math.max(0,cs-10);
    document.getElementById('c-score').textContent=cs;
    fb.className='gm-feedback wrong';
    fb.innerHTML='<strong>Not it.</strong> Minus 10 points. Try again.';
  }
};

window.cHint=function(){
  cs=Math.max(0,cs-20);
  document.getElementById('c-score').textContent=cs;
  var fb=document.getElementById('c-fb');
  fb.className='gm-feedback wrong';
  fb.innerHTML='<strong>Hint:</strong> '+CIPH[ci].h;
};

document.getElementById('c-in').addEventListener('keydown',function(e){ if(e.key==='Enter') cCheck(); });
cRender();

/* ─── GAME 3: PASSWORD LAB ─────────────── */
var COMMON=["password","123456","qwerty","admin","letmein","welcome","monkey","dragon","football","iloveyou","abc123","kenya","safaricom","nairobi","password1","admin123"];

function fmtTime(sec){
  if(sec<1) return "instantly";
  var u=[["second",60],["minute",60],["hour",24],["day",365],["year",100],["century",Infinity]];
  var v=sec;
  for(var i=0;i<u.length;i++){
    if(v<u[i][1]) return Math.round(v)+" "+u[i][0]+(Math.round(v)===1?"":"s");
    v=v/u[i][1];
  }
  return "longer than the age of the universe";
}

document.getElementById('w-in').addEventListener('input',function(){
  var p=this.value;
  var pool=0;
  if(/[a-z]/.test(p)) pool+=26;
  if(/[A-Z]/.test(p)) pool+=26;
  if(/[0-9]/.test(p)) pool+=10;
  if(/[^a-zA-Z0-9]/.test(p)) pool+=33;

  var lower=p.toLowerCase();
  var isCommon=COMMON.some(function(c){return lower.indexOf(c)!==-1;});
  var bits = p.length ? Math.round(p.length*Math.log2(pool||1)) : 0;
  if(isCommon) bits=Math.min(bits,18);

  var guesses=Math.pow(2,bits)/2;
  var secs=guesses/1e11;

  document.getElementById('w-bits').textContent=bits;

  var pct=Math.min(100,(bits/90)*100);
  var bar=document.getElementById('w-bar');
  bar.style.width=pct+'%';
  var col = bits<28?'#ff5f56' : bits<45?'#ffbd2e' : bits<65?'#7eb2ec' : '#27c93f';
  bar.style.background=col;

  var lbl = !p.length?'Type something to begin' :
            bits<28?'Very weak' : bits<45?'Weak' : bits<65?'Reasonable' : bits<80?'Strong' : 'Very strong';
  var el=document.getElementById('w-label');
  el.textContent=lbl+(isCommon&&p.length?' — contains a common word or pattern':'');
  el.style.color=p.length?col:'';

  document.getElementById('w-crack').textContent = p.length ? 'Offline crack time: '+fmtTime(secs) : '';

  document.getElementById('w-c1').className = p.length>=12?'hit':'';
  document.getElementById('w-c2').className = (/[a-z]/.test(p)&&/[A-Z]/.test(p))?'hit':'';
  document.getElementById('w-c3').className = /[0-9]/.test(p)?'hit':'';
  document.getElementById('w-c4').className = /[^a-zA-Z0-9]/.test(p)?'hit':'';
  document.getElementById('w-c5').className = (p.length&&!isCommon)?'hit':'';
});

/* ─── GAME 4: PORT MATCH ───────────────── */
var PAIRS=[
  ["22","SSH"],["80","HTTP"],["443","HTTPS"],["53","DNS"],
  ["3389","RDP"],["21","FTP"],["445","SMB"],["6379","Redis"]
];
var mDeck=[], mUp=[], mMoves=0, mFound=0, mLock=false;

window.mInit=function(){
  mDeck=[]; mUp=[]; mMoves=0; mFound=0; mLock=false;
  PAIRS.forEach(function(p,i){
    mDeck.push({id:i,txt:p[0],type:'port'});
    mDeck.push({id:i,txt:p[1],type:'svc'});
  });
  for(var i=mDeck.length-1;i>0;i--){
    var j=Math.floor(Math.random()*(i+1));
    var t=mDeck[i]; mDeck[i]=mDeck[j]; mDeck[j]=t;
  }
  var g=document.getElementById('m-grid');
  g.innerHTML='';
  mDeck.forEach(function(c,idx){
    var d=document.createElement('div');
    d.className='gm-tile';
    d.dataset.idx=idx;
    d.innerHTML='<span class="q">?</span><span class="face">'+c.txt+'</span>';
    d.addEventListener('click',function(){ mFlip(idx,d); });
    g.appendChild(d);
  });
  document.getElementById('m-moves').textContent=0;
  document.getElementById('m-found').textContent=0;
  document.getElementById('m-fb').className='gm-feedback';
};

function mFlip(idx,el){
  if(mLock||el.classList.contains('up')||el.classList.contains('done')) return;
  el.classList.add('up');
  mUp.push({idx:idx,el:el});
  if(mUp.length===2){
    mMoves++;
    document.getElementById('m-moves').textContent=mMoves;
    mLock=true;
    var a=mDeck[mUp[0].idx], b=mDeck[mUp[1].idx];
    if(a.id===b.id && a.type!==b.type){
      setTimeout(function(){
        mUp.forEach(function(u){u.el.classList.remove('up');u.el.classList.add('done');});
        mUp=[]; mLock=false; mFound++;
        document.getElementById('m-found').textContent=mFound;
        if(mFound===PAIRS.length){
          var fb=document.getElementById('m-fb');
          fb.className='gm-feedback right';
          var rating = mMoves<=12?'Excellent recall.' : mMoves<=18?'Good.' : 'Cleared it.';
          fb.innerHTML='<strong>All matched in '+mMoves+' moves. '+rating+'</strong> These eight are the ports you will meet on almost every scan. 6379 is the one people miss, because Redis sits outside nmap default top 1000.';
        }
      },420);
    } else {
      setTimeout(function(){
        mUp.forEach(function(u){u.el.classList.remove('up');});
        mUp=[]; mLock=false;
      },750);
    }
  }
}

mInit();

})();
</script>
