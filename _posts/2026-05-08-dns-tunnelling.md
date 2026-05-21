---
title: "DNS Tunnelling: How Attackers Hide Command and Control Traffic in Plain Sight"
date: 2026-05-08 09:00:00 +0300
categories: [Cybersecurity, Networking]
tags: [dns, c2, network analysis, blue team, soc, threat detection, packet analysis]
description: DNS is one of the most trusted protocols on any network. That trust is exactly why attackers use it to hide command and control traffic. Here is what DNS tunnelling looks like and how to detect it.
---

## Introduction

Every security team blocks malicious IP addresses. Many block suspicious domains. Very few adequately monitor DNS traffic for abuse.

DNS tunnelling exploits this blind spot. It encodes data inside DNS queries and responses, using the DNS protocol as a covert communications channel. Because DNS traffic is almost universally allowed through firewalls (block DNS and your network stops working), it makes for an effective and stealthy command and control (C2) or data exfiltration channel.

---

## How DNS Works (Briefly)

When your machine needs to resolve `example.com` to an IP address, it sends a DNS query to a resolver. The resolver walks up the DNS hierarchy until it gets an authoritative answer and returns it to you.

What matters here: this query-response exchange passes through firewalls almost without question. It is fundamental infrastructure.

---

## How Attackers Abuse It

In a DNS tunnelling attack, the attacker controls both the malware on the victim machine and an authoritative DNS server for a domain they own.

The malware encodes data (commands from the attacker, or stolen data from the victim) as subdomains of the attacker's domain. A query like:

```
YWRtaW5wYXNzd29yZA==.exfil.attacker-domain.com
```

...looks like a DNS lookup. But the long, base64-encoded subdomain carries a payload. The attacker's authoritative DNS server receives this query (because all DNS for `attacker-domain.com` routes to them), decodes the payload, and responds with encoded data in the DNS reply.

No direct connection to a suspicious IP is needed. The entire C2 channel runs over DNS.

Tools like `dnscat2` and `iodine` make this straightforward to implement, and many advanced threat actors build custom DNS tunnelling capabilities into their implants.

---

## What DNS Tunnelling Looks Like

DNS tunnelling has distinctive fingerprints if you know what to look for:

**Unusually long subdomain strings:**
Normal DNS queries have short, human-readable subdomains. Queries with subdomains that are 50+ characters of what looks like random alphanumeric data are a strong indicator.

**High query volume to a single domain:**
A compromised host that is actively tunnelling will generate significantly more DNS queries than normal, often to a single rarely-seen domain.

**Queries for domains with no prior history:**
Brand-new domains receiving heavy query volume from internal hosts warrant investigation.

**Unusual DNS record types:**
Attackers sometimes encode data in TXT or NULL record responses, not just A record responses. Seeing TXT record queries in volume is unusual for normal browse traffic.

**Large DNS response sizes:**
Standard DNS responses are small. Responses carrying encoded payloads in TXT fields are noticeably larger.

---

## Detection in a SOC Environment

DNS logging is your starting point. Many organisations do not log DNS queries at all, which is a major visibility gap. If your environment does not have DNS logging enabled, that is the first fix.

Once you have logs, apply these queries:

- Flag any DNS query where the subdomain component exceeds 40 characters.
- Alert on hosts generating more than a threshold number of DNS queries per minute to a single domain outside of normal business applications.
- Cross-reference queried domains against threat intelligence for newly registered or low-reputation domains.
- Look for TXT record queries originating from endpoints, which is unusual in most environments.

Tools like Zeek (formerly Bro) are excellent for DNS anomaly detection at scale, generating structured logs from raw packet capture that feed directly into a SIEM.

---

## Key Takeaways

- DNS is a trusted protocol that bypasses most perimeter controls, making it an attractive C2 and exfiltration channel.
- DNS tunnelling encodes data as subdomains and DNS record content, routing communications through the attacker's authoritative server.
- Key detection signals include unusually long subdomains, high query volume, large response sizes, and unusual record types.
- DNS logging is a prerequisite. If you are not logging DNS queries, you cannot detect this attack class.

The quietest traffic on your network is often the most suspicious. DNS is worth listening to.
