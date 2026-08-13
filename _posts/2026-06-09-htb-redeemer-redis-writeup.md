---
title: "HTB: Redeemer — Exploiting an Unauthenticated Redis Instance"
date: 2026-06-09 11:00:00 +0300
categories: [Labs, HTB]
tags: [hackthebox, redis, misconfiguration, enumeration, starting point, reconnaissance, blue team, soc]
description: A walkthrough of the Hack The Box Redeemer machine. No exploits, no code. Just a misconfigured Redis instance exposed to the network with no authentication and four keys waiting to be read.
image:
  path: https://images.unsplash.com/photo-1484807352052-23338990c6c6?w=1200&h=500&fit=crop&q=80
  alt: Exposed database service on a server
---

## Overview

**Platform:** Hack The Box
**Machine:** Redeemer
**Difficulty:** Very Easy
**Category:** Starting Point
**Tags:** Redis, Misconfiguration, Unauthenticated Access

Redeemer introduces one of the most common and dangerous misconfigurations in real-world infrastructure: a Redis instance exposed to the network with no authentication. No exploit code required. No CVE to look up. The entire attack chain is connecting to an open port and reading data that should never have been accessible in the first place.

This is exactly the kind of misconfiguration SOC analysts and penetration testers encounter on real engagements.

---

## Reconnaissance

### Step 1: Confirm Host is Alive

```bash
ping -c 4 10.129.68.163
```

TTL of 63 confirms a Linux target. Windows typically returns TTL 128, Linux returns 64 with one hop decrement giving 63.

### Step 2: Initial Nmap Scan

```bash
nmap -sC -sV -oN nmap_initial.txt 10.129.68.163
```

All 1000 common ports came back closed. This is the first important lesson of this machine: the default nmap scan only covers the top 1000 ports. Redis runs on port 6379, which sits outside that range. A clean result does not mean nothing is running.

### Step 3: Full Port Scan

```bash
nmap -p- --min-rate 5000 -oN nmap_allports.txt 10.129.68.163
```

**Result:**

```
PORT     STATE SERVICE
6379/tcp open  redis
```

There it is. Redis running on its default port, completely missed by the initial scan. The `--min-rate 5000` flag pushes nmap to send at least 5000 packets per second, making the full port scan fast enough to be practical.

**Always run a full port scan.** This is the single biggest lesson from this machine.

---

## Enumeration

### Step 4: Connect to Redis

```bash
redis-cli -h 10.129.68.163
```

Connected immediately. No username prompt. No password prompt. The instance had zero authentication configured, which means anyone on the network who knows the port is open has full read and write access to the database.

### Step 5: Pull Server Information

```
info
```

Key findings from the output:

- Redis version: 5.0.7
- OS: Linux 5.4.0-77-generic x86_64
- Keyspace: `db0:keys=4` (four keys stored in database 0)

The keyspace line is the most important. It tells us exactly how much data is stored and which database it lives in. Four keys in database 0.

### Step 6: List All Keys

```
keys *
```

Output:

```
1) "numb"
2) "flag"
3) "stor"
4) "temp"
```

A key literally named `flag` is sitting there in plain sight.

---

## Exploitation

### Step 7: Read the Flag

```
get flag
```

**Flag:** `03e1d2b376c37ab3f5319922053953eb`

That is the entire attack. Connect, enumerate, read. No exploit required because the misconfiguration did all the work for the attacker.

---

## Why This Matters Beyond CTFs

Redis is extremely common in production infrastructure. It is used as a caching layer, a session store, a message broker, and a job queue. Many development teams stand it up quickly without thinking through the security implications, and it ends up exposed with default or no authentication.

In real-world attacks, an unauthenticated Redis instance is not just a data theft risk. It is a potential remote code execution vector.

**SSH Key Injection:** If the Redis process has write permissions to the filesystem, an attacker can write their own SSH public key into the `authorized_keys` file of the service account running Redis. From there, they have persistent shell access to the server.

**Cron-based Reverse Shells:** An attacker can write a cron job payload to `/etc/cron.d/` via Redis if file write permissions allow it. The cron daemon picks it up automatically and executes the payload.

**Config File Overwrite:** Redis can be configured to write its dataset to disk at a specified path. An attacker can redirect this to overwrite sensitive configuration files.

None of these require any vulnerability in Redis itself. They all rely entirely on the misconfiguration of running Redis without authentication and binding it to an interface accessible from outside localhost.

---

## The Fix

Two lines in `redis.conf` prevent all of this:

```
requirepass YourStrongPasswordHere
bind 127.0.0.1
```

`requirepass` enforces password authentication on every connection. `bind 127.0.0.1` ensures Redis only listens on the loopback interface and is not reachable from the network at all. Both together mean even a compromised network position gives an attacker nothing.

---

## Commands Reference

| Command | Purpose |
|---|---|
| `nmap -p- --min-rate 5000` | Full port scan across all 65535 ports |
| `redis-cli -h <ip>` | Connect to a remote Redis instance |
| `info` | Pull server info, version, OS, keyspace stats |
| `keys *` | List all keys in the current database |
| `get <key>` | Read the value of a specific key |
| `select <index>` | Switch to a different database (0-15) |

---

## Key Takeaways

The default nmap scan covers 1000 ports. Production services often run outside that range. A full `-p-` scan is non-negotiable.

An unauthenticated Redis instance is not just a data exposure risk. It is a potential foothold for RCE via SSH key injection or cron job manipulation.

Misconfigurations cause more real-world breaches than zero-day vulnerabilities. The skill of finding exposed services with weak or missing authentication is directly transferable to red team assessments and SOC threat hunting.

The remediation is two lines of configuration. The gap between a vulnerable and a secure Redis deployment is a five-minute fix.

---

**Verified completion:** [HTB Achievement](https://labs.hackthebox.com/achievement/machine/3045385/472)

*HTB Starting Point: Redeemer | Completed by Glenn | Lab Writeup*
