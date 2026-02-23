---
title: "Understanding the Cyber Kill Chain: A SOC Analyst's Perspective"
date: 2026-02-23 08:00:00 +0300
categories: [Cybersecurity, Frameworks]
tags: [cyber kill chain, threat detection, soc, incident response, mitre, blue team]
author: Ongalo Glenn
description: Breaking down the Cyber Kill Chain framework and how SOC analysts use it to detect, disrupt, and respond to cyberattacks at every stage.
---

## Introduction

Every cyberattack tells a story. An attacker doesn't just appear inside your network — they follow a sequence of steps, making decisions at each stage to move closer to their objective. Understanding that sequence is one of the most powerful tools a SOC analyst has.

The **Cyber Kill Chain** is a framework developed by Lockheed Martin in 2011 that maps the stages of a cyberattack from the attacker's first move to their final goal. Originally adapted from military targeting doctrine, it has become a foundational model in defensive cybersecurity.

In this post I'll break down each stage of the Kill Chain, explain what attackers are doing at each step, and — most importantly — describe what a SOC analyst should be looking for to detect and disrupt them.

---

## The 7 Stages of the Cyber Kill Chain

### 1. Reconnaissance

**What the attacker is doing:**  
Before launching an attack, the adversary gathers as much information about the target as possible. This includes identifying employees via LinkedIn, finding exposed subdomains, scanning for open ports, discovering email formats, and researching technologies in use.

This phase is largely passive and happens *outside* the target's network, making it the hardest stage to detect.

**Tools attackers use:**
- `Shodan` — scanning for internet-exposed services
- `theHarvester` — email and domain harvesting
- `Maltego` — open-source intelligence mapping
- Google dorking — finding sensitive exposed files

**What to look for as a SOC analyst:**
- Unusual spikes in DNS queries for your domain
- Port scanning activity from external IPs hitting your perimeter
- Multiple failed login attempts probing for valid usernames

> **Key insight:** You won't catch most reconnaissance in real time. But threat intelligence feeds and honeypots can surface early signals of someone mapping your environment.

---

### 2. Weaponisation

**What the attacker is doing:**  
The attacker combines an exploit with a malicious payload — typically creating a weaponised document (e.g. a Word file with a malicious macro), a drive-by download, or a custom piece of malware. This stage happens entirely on the attacker's side; you won't see it on your network.

**Common weapons:**
- Malicious Office documents with embedded macros
- PDF files exploiting reader vulnerabilities
- Custom malware packaged with legitimate-looking installers

**What to look for as a SOC analyst:**  
You can't observe weaponisation directly, but you can use threat intelligence to identify known malware families and exploit kits being used against organisations in your sector. Threat intel subscriptions and ISAC feeds help here.

---

### 3. Delivery

**What the attacker is doing:**  
The weapon is transmitted to the target. This is the first stage where the attack enters your environment — and your best early opportunity to stop it.

**Common delivery mechanisms:**
- **Phishing emails** — the most common vector by far
- **Watering hole attacks** — compromising websites the target frequently visits
- **USB drops** — physically leaving infected drives in target locations
- **Supply chain compromise** — embedding malware in trusted software updates

**What to look for as a SOC analyst:**
- Email gateway alerts for suspicious attachments (`.exe`, `.docm`, `.iso` in emails)
- Emails with mismatched sender domains (e.g. display name says "IT Support" but domain is external)
- Users visiting newly registered or low-reputation domains
- Antivirus alerts on downloaded files

> **Key insight:** Email filtering, DNS filtering, and user awareness training are your primary defences here. A well-tuned email security gateway stops the majority of attacks at this stage.

---

### 4. Exploitation

**What the attacker is doing:**  
The malicious payload triggers, exploiting a vulnerability in the target system — whether in software, the operating system, or human behaviour (e.g. a user enabling a macro). Code executes on the victim's machine for the first time.

**Common exploitation techniques:**
- Macro execution in Office documents
- Browser or plugin vulnerabilities (unpatched Flash, Java)
- Zero-day exploits targeting unpatched systems
- Social engineering the user into running a file

**What to look for as a SOC analyst:**
- Process creation events from unexpected parents (e.g. `winword.exe` spawning `powershell.exe`)
- Windows Event ID **4688** — new process creation with suspicious command lines
- Antivirus or EDR alerts firing on a host
- `wscript.exe` or `cscript.exe` executing from temp directories

> **Key insight:** This is where EDR (Endpoint Detection & Response) tools shine. Behavioural detections — not just signature-based AV — catch exploitation that bypasses traditional defences.

---

### 5. Installation

**What the attacker is doing:**  
To maintain access beyond the initial session, the attacker installs a persistent backdoor or Remote Access Trojan (RAT). This ensures they can return to the compromised system even after a reboot or credential reset.

**Common persistence mechanisms:**
- Registry run keys (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`)
- Scheduled tasks
- DLL hijacking
- Startup folder entries
- Service installation

**What to look for as a SOC analyst:**
- New scheduled tasks created outside of business hours or by unexpected users
- Registry modifications to run keys — Windows Event ID **4657**
- New services being installed — Windows Event ID **7045**
- Files written to `%AppData%`, `%Temp%`, or `%ProgramData%` directories
- Unsigned binaries in unusual locations

---

### 6. Command & Control (C2)

**What the attacker is doing:**  
The installed malware "phones home" to an attacker-controlled server, establishing a command and control channel. This channel allows the attacker to issue commands, exfiltrate data, and move through the network. Modern C2 frameworks often disguise traffic to blend in with normal web traffic (e.g. using HTTPS or DNS tunnelling).

**Popular C2 frameworks (used by attackers and red teams):**
- Cobalt Strike
- Metasploit
- Sliver
- Havoc

**What to look for as a SOC analyst:**
- Outbound connections to newly registered or low-reputation domains
- Beaconing behaviour — regular, periodic outbound connections at consistent intervals
- DNS queries for unusually long or encoded subdomains (DNS tunnelling)
- HTTPS traffic to IPs with no corresponding domain name (direct IP C2)
- Large data transfers at unusual hours

> **Key insight:** Beaconing is one of the most reliable C2 indicators. If a host is making an outbound connection to the same external IP every 60 seconds like clockwork — that's a red flag worth investigating.

---

### 7. Actions on Objectives

**What the attacker is doing:**  
With a foothold established and C2 active, the attacker finally pursues their goal. This varies by threat actor — ransomware gangs encrypt files, espionage actors exfiltrate sensitive documents, hacktivists deface websites, and insiders abuse access for personal gain.

**Common objectives:**
- **Data exfiltration** — stealing credentials, PII, intellectual property
- **Ransomware deployment** — encrypting files across the network
- **Lateral movement** — pivoting to higher-value systems using stolen credentials
- **Destruction** — wiping systems or corrupting data

**What to look for as a SOC analyst:**
- Mass file access or modification events on file servers
- Credential dumping tools (e.g. Mimikatz) — Event ID **4624** with unusual logon types
- Large volumes of data being compressed or transferred externally
- Lateral movement via PsExec, WMI, or RDP to systems the user doesn't normally access
- Shadow copy deletion — a strong ransomware pre-cursor (`vssadmin delete shadows`)

---

## Why the Kill Chain Matters for SOC Analysts

The Cyber Kill Chain is more than a theoretical model — it's a practical thinking tool for triage and investigation. When you receive an alert, asking *"where in the Kill Chain does this fit?"* immediately tells you:

- **How far along** the attacker might be
- **What likely happened before** this alert (which you may have missed)
- **What's likely to happen next** (which you can get ahead of)

It also shifts the mindset from *reactive* to *proactive*. An attacker must complete every stage to succeed. A defender only needs to disrupt one.

---

## Kill Chain vs. MITRE ATT&CK

The Kill Chain is a high-level model — great for framing an investigation. **MITRE ATT&CK** goes deeper, cataloguing the specific techniques attackers use at each stage. In practice, SOC analysts use both:

| Framework | Best Used For |
|---|---|
| Cyber Kill Chain | Understanding the overall attack narrative |
| MITRE ATT&CK | Mapping specific techniques, hunting for TTPs |

---

## Final Thoughts

Understanding the Cyber Kill Chain has fundamentally changed how I approach security analysis. Rather than treating alerts as isolated events, I now think about each one as a potential data point in a larger attack story.

As I continue building my skills toward a SOC Analyst role, frameworks like this help me think like both an attacker and a defender — which is ultimately what effective threat detection requires.

---

*If you found this useful or have thoughts to share, connect with me on [LinkedIn](https://www.linkedin.com/in/ongalo-glenn) or check out my other write-ups on this site.*
