---
title: "Building a SOC in Kenya: What Actually Works With a Real Budget"
date: 2026-08-11 09:00:00 +0300
categories: [Cybersecurity, Kenya]
tags: [soc, detection engineering, kenya, siem, wazuh, mitre, blue team, threat detection, incident response]
description: 74% of East African organisations rank cyber risk as a top concern but only 29% run crisis simulations. The gap is not awareness. It is operational capability. Here is how to build detection capability without a tier-one budget.
image:
  path: https://images.unsplash.com/photo-1460925895917-afdab827c52f?w=1200&h=500&fit=crop&q=80
  alt: Security operations dashboards and monitoring
---

## The Execution Gap

A 2026 regional cybersecurity report described the defining problem in East African security as an execution gap: **74% of organisations rank cyber risk as a top strategic concern, but only 29% conduct regular tabletop exercises** to simulate crises.

Awareness is not the constraint. Boards understand cyber risk. Budgets have increased. What has not materialised at the same rate is operational detection and response capability.

Meanwhile KE-CIRT/CC issued 19.9 million cyber threat advisories in a single quarter. That volume of advisory output producing limited defensive change suggests the bottleneck is capacity to act, not information to act on.

---

## Start With Visibility, Not Tools

The most common failure in building a security operations capability is buying a SIEM first. A SIEM with no logs is an expensive database.

Work in this order.

### 1. Asset Inventory

You cannot monitor what you do not know exists. Before any tooling, establish:

- Every server, its function, its owner, and its criticality
- Every network segment and what connects between them
- Every internet-facing service
- Every SaaS application holding company or customer data
- Every third party with system access

This is unglamorous and it is the foundation. Most organisations discover systems nobody remembered during this exercise, which is itself a finding.

### 2. Log Sources in Priority Order

Not all logs are equal. In order of detection value per unit of effort:

**Tier 1, non-negotiable:**
- Windows Security logs from domain controllers, which is where credential attacks are visible
- Authentication logs from your identity provider (Entra ID, Okta, or on-premise AD)
- Firewall and perimeter device logs
- VPN authentication logs

**Tier 2, high value:**
- Endpoint telemetry from EDR, or Sysmon if EDR is not affordable
- DNS query logs, which most organisations do not collect and which reveal C2 and exfiltration
- Web proxy or gateway logs
- Cloud provider audit logs

**Tier 3, valuable as maturity grows:**
- Application and database audit logs
- Email gateway logs
- Core banking or business system transaction logs

DNS logging deserves particular emphasis. It is inexpensive, generates high-signal data, and is absent from most Kenyan environments. Command and control beaconing and DNS tunnelling are both invisible without it.

### 3. Platform Choice

There are workable options at every budget level.

**Wazuh** is open source, includes agent-based endpoint monitoring, file integrity monitoring, and log analysis, and runs on hardware you already have. For an organisation with no existing capability, it delivers meaningful detection at infrastructure cost only.

**Elastic Security** offers a free tier with strong search performance and a large community detection rule set.

**Microsoft Sentinel** makes sense if you are already Microsoft 365 E5, since much of the log ingestion is included and integration with Entra ID and Defender is native.

**Commercial SIEM** platforms deliver more out of the box but licence costs scale with data volume, which becomes the constraint quickly.

The platform matters far less than whether anyone is actually reviewing the alerts it generates.

---

## Detection Content That Matters

Do not attempt to detect everything. Build detections for the techniques actually being used against Kenyan organisations, mapped to MITRE ATT&CK.

Starting set, in priority order:

| Technique | Detection | Log Source |
|---|---|---|
| T1110 Brute Force | High volume of failed authentications from a single source | Windows Security 4625, VPN logs |
| T1078 Valid Accounts | Impossible travel, unusual hours, new device | Identity provider logs |
| T1136 Create Account | New account creation, especially in privileged groups | Windows Security 4720, 4728 |
| T1003 Credential Dumping | LSASS access from unexpected processes | EDR, Sysmon Event 10 |
| T1490 Inhibit Recovery | Shadow copy deletion commands | Windows Security 4688 |
| T1071 C2 over DNS | Long subdomains, high query volume to single domain | DNS logs |
| T1567 Exfiltration to Cloud | Large uploads to file sharing services | Proxy logs |
| T1021 Remote Services | Unusual RDP or SMB between workstations | Windows Security 4624 type 3 and 10 |

Eight well-tuned detections that someone reviews daily beat four hundred untuned rules that nobody looks at.

### Baseline Before You Alert

Every detection needs a baseline. Run each new rule in monitoring mode for two weeks. Document what fires and why. Tune out the legitimate activity. Only then enable alerting.

A rule that generates fifty false positives daily will be ignored within a week, and the one true positive will be ignored with it.

---

## Process Before Headcount

A 24/7 SOC requires roughly eight to ten analysts. Most Kenyan organisations cannot justify that. What they can do is establish process.

**Defined triage procedure.** For every alert type, a documented procedure: what it means, what to check, what determines escalation, and who to contact. This lets a less experienced analyst handle tier-one triage effectively.

**Escalation paths with names and numbers.** Who gets called at 2am, and what is the backup if they do not answer.

**Incident classification.** Severity levels with defined criteria and response time expectations for each.

**Documented playbooks** for the incident types you are most likely to face: ransomware, business email compromise, compromised credentials, data exfiltration, and insider misuse.

**Post-incident review** after every significant incident. What was detected, what was missed, what needs to change. This is how detection improves.

---

## Tabletop Exercises

Only 29% of regional organisations run them. This is the highest return per shilling spent in the entire security programme.

A tabletop costs a conference room and three hours. It requires no tooling. It surfaces exactly the gaps that matter: unclear decision authority, missing contact details, undocumented dependencies, and untested assumptions.

Run one quarterly. Rotate the scenario: ransomware, data breach with ODPC notification obligation, BEC loss, insider fraud discovery, critical vendor compromise.

Include people outside IT. Legal, communications, finance, and executive leadership all have decisions to make during an incident, and they should make them for the first time in a conference room, not in production.

---

## Building the Team

The skills gap is real. Experienced security professionals in Kenya are scarce and expensive relative to demand.

The practical path for most organisations is developing internally. Network administrators, system administrators, and developers already understand the environment, which is the hardest part to teach. Detection engineering and incident response can be learned.

Structured paths that work: Hack The Box Academy, TryHackMe, Blue Team Labs Online, and the Cyber Shujaa programme for foundational training. The differentiator is applying the learning to your own environment, building real detections against real logs.

An analyst who has built ten detections against your infrastructure is more valuable than one who has a certification but has never seen your logs.

---

## Key Takeaways

- 74% of East African organisations rank cyber risk highly but only 29% run tabletop exercises. The gap is operational capability, not awareness.
- Build in order: asset inventory, then log collection, then platform, then detection content. Buying a SIEM first is the most common failure.
- DNS logging is the highest-value, lowest-cost log source that most Kenyan organisations do not collect.
- Eight well-tuned detections reviewed daily beat four hundred untuned rules nobody reads. Baseline every rule before enabling alerts.
- Tabletop exercises deliver the highest risk reduction per shilling of any security activity and require no tooling investment.

*Written by Glenn Ongalo | Nairobi, Kenya*
