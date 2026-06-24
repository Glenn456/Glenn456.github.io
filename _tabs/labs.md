---
layout: page
title: Labs
icon: fas fa-flask
order: 2
permalink: /labs/
---

<style>
.labs-header {
  border-left: 3px solid var(--link-color);
  padding: 12px 16px;
  margin-bottom: 2rem;
  background: var(--card-bg);
  border-radius: 0 6px 6px 0;
}
.labs-header p { margin: 0; font-size: 0.9rem; opacity: 0.8; }
.platform-section { margin-bottom: 2.5rem; }
.platform-title {
  font-size: 0.75rem;
  letter-spacing: 2px;
  text-transform: uppercase;
  opacity: 0.5;
  margin-bottom: 1rem;
  padding-bottom: 6px;
  border-bottom: 1px solid var(--border-color);
}
.lab-card {
  display: flex;
  align-items: flex-start;
  gap: 14px;
  padding: 14px 0;
  border-bottom: 1px solid var(--border-color);
  text-decoration: none;
  color: inherit;
  transition: all 0.2s;
}
.lab-card:hover { padding-left: 6px; }
.lab-card:hover .lab-title { color: var(--link-color); }
.lab-badge {
  min-width: 70px;
  text-align: center;
  padding: 3px 8px;
  border-radius: 4px;
  font-size: 0.7rem;
  font-weight: 600;
  letter-spacing: 0.5px;
  margin-top: 3px;
}
.badge-veryeasy { background: rgba(0,255,65,0.15); color: #00cc44; border: 1px solid rgba(0,255,65,0.3); }
.badge-easy     { background: rgba(0,170,255,0.15); color: #00aaff; border: 1px solid rgba(0,170,255,0.3); }
.badge-medium   { background: rgba(255,170,0,0.15);  color: #ffaa00; border: 1px solid rgba(255,170,0,0.3); }
.badge-hard     { background: rgba(255,68,68,0.15);  color: #ff4444; border: 1px solid rgba(255,68,68,0.3); }
.lab-info { flex: 1; }
.lab-title { font-size: 0.97rem; font-weight: 600; margin-bottom: 4px; }
.lab-meta { font-size: 0.78rem; opacity: 0.55; }
.lab-tags { margin-top: 5px; display: flex; flex-wrap: wrap; gap: 5px; }
.lab-tag {
  font-size: 0.68rem;
  padding: 1px 7px;
  border-radius: 3px;
  background: var(--tag-bg, rgba(128,128,128,0.1));
  opacity: 0.7;
}
.stats-row {
  display: flex; gap: 16px; flex-wrap: wrap;
  margin-bottom: 2rem;
}
.stat-box {
  flex: 1; min-width: 80px;
  text-align: center;
  padding: 14px 10px;
  background: var(--card-bg);
  border-radius: 8px;
  border: 1px solid var(--border-color);
}
.stat-num { font-size: 1.6rem; font-weight: 700; color: var(--link-color); }
.stat-lbl { font-size: 0.7rem; opacity: 0.5; letter-spacing: 1px; text-transform: uppercase; margin-top: 2px; }
.htb-link {
  display: inline-flex; align-items: center; gap: 8px;
  padding: 8px 16px; border-radius: 6px;
  background: rgba(159,239,0,0.1);
  border: 1px solid rgba(159,239,0,0.3);
  color: #9fef00; font-size: 0.82rem;
  text-decoration: none; margin-bottom: 2rem;
  transition: all 0.2s;
}
.htb-link:hover { background: rgba(159,239,0,0.18); color: #9fef00; }
</style>

<div class="labs-header">
  <strong>Hands-on lab writeups from Hack The Box, Blue Team Labs Online, and OverTheWire.</strong>
  <p style="margin-top:6px;">Each writeup documents methodology, commands, findings, and lessons learned. Theory without practice means nothing - this is the practice.</p>
</div>

<div class="stats-row">
  <div class="stat-box">
    <div class="stat-num">4</div>
    <div class="stat-lbl">Completed</div>
  </div>
  <div class="stat-box">
    <div class="stat-num">3</div>
    <div class="stat-lbl">HTB Machines</div>
  </div>
  <div class="stat-box">
    <div class="stat-num">1</div>
    <div class="stat-lbl">DFIR</div>
  </div>
  <div class="stat-box">
    <div class="stat-num">17</div>
    <div class="stat-lbl">OTW Bandit</div>
  </div>
</div>

<a class="htb-link" href="https://labs.hackthebox.com/achievement/machine/3045385/472" target="_blank">
  ⬡ View HTB Profile & Achievements
</a>

<div class="platform-section">
  <div class="platform-title">// Hack The Box - Sherlocks (DFIR)</div>

  <a class="lab-card" href="/posts/htb-sherlock-brutus-dfir-writeup/">
    <span class="lab-badge badge-veryeasy">VERY EASY</span>
    <div class="lab-info">
      <div class="lab-title">Brutus - Linux Server Compromise Investigation</div>
      <div class="lab-meta">DFIR &nbsp;·&nbsp; auth.log + wtmp &nbsp;·&nbsp; Brute Force → Persistence</div>
      <div class="lab-tags">
        <span class="lab-tag">auth.log</span>
        <span class="lab-tag">wtmp</span>
        <span class="lab-tag">brute force</span>
        <span class="lab-tag">T1136.001</span>
        <span class="lab-tag">MITRE ATT&CK</span>
      </div>
    </div>
  </a>
</div>

<div class="platform-section">
  <div class="platform-title">// Hack The Box - Starting Point</div>

  <a class="lab-card" href="/posts/htb-redeemer-redis-writeup/">
    <span class="lab-badge badge-veryeasy">VERY EASY</span>
    <div class="lab-info">
      <div class="lab-title">Redeemer - Unauthenticated Redis Instance</div>
      <div class="lab-meta">Starting Point &nbsp;·&nbsp; Misconfiguration &nbsp;·&nbsp; Redis Port 6379</div>
      <div class="lab-tags">
        <span class="lab-tag">redis</span>
        <span class="lab-tag">misconfiguration</span>
        <span class="lab-tag">enumeration</span>
        <span class="lab-tag">nmap</span>
        <span class="lab-tag">unauthenticated access</span>
      </div>
    </div>
  </a>
  <a class="lab-card" href="/posts/htb-cap-writeup/">
    <span class="lab-badge badge-easy">EASY</span>
    <div class="lab-info">
      <div class="lab-title">Cap - IDOR to Root via Linux Capabilities</div>
      <div class="lab-meta">Starting Point &nbsp;·&nbsp; IDOR + FTP Creds + cap_setuid Privilege Escalation</div>
      <div class="lab-tags">
        <span class="lab-tag">idor</span>
        <span class="lab-tag">pcap analysis</span>
        <span class="lab-tag">ftp</span>
        <span class="lab-tag">linux capabilities</span>
        <span class="lab-tag">privilege escalation</span>
      </div>
    </div>
  </a>
</div>

<div class="platform-section">
  <div class="platform-title">// OverTheWire - Bandit</div>

  <div class="lab-card" style="cursor:default;">
    <span class="lab-badge badge-easy">IN PROGRESS</span>
    <div class="lab-info">
      <div class="lab-title">Bandit - Linux Command Line & Privilege Escalation</div>
      <div class="lab-meta">OverTheWire &nbsp;·&nbsp; Currently at Level 17-18</div>
      <div class="lab-tags">
        <span class="lab-tag">linux</span>
        <span class="lab-tag">bash</span>
        <span class="lab-tag">ssh</span>
        <span class="lab-tag">file permissions</span>
        <span class="lab-tag">privilege escalation</span>
      </div>
    </div>
  </div>
</div>

<div class="platform-section">
  <div class="platform-title">// Blue Team Labs Online</div>

  <div class="lab-card" style="cursor:default;">
    <span class="lab-badge badge-easy">IN PROGRESS</span>
    <div class="lab-info">
      <div class="lab-title">Blue Team Labs - Defensive Security Scenarios</div>
      <div class="lab-meta">Blue Team Labs Online &nbsp;·&nbsp; Just started</div>
      <div class="lab-tags">
        <span class="lab-tag">blue team</span>
        <span class="lab-tag">log analysis</span>
        <span class="lab-tag">incident response</span>
        <span class="lab-tag">threat detection</span>
      </div>
    </div>
  </div>
</div>

<p style="font-size:0.8rem; opacity:0.4; margin-top:2rem; text-align:center;">
  Updated as labs are completed. Writeups published for every machine.
</p>
