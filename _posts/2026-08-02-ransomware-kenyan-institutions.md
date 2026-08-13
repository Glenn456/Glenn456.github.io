---
title: "Ransomware Is Coming for Kenya's Public Institutions"
date: 2026-08-02 09:00:00 +0300
categories: [Cybersecurity, Kenya]
tags: [ransomware, kenya, critical infrastructure, incident response, backup, detection, blue team, soc]
description: Kenya Power, Kenya Railways, the NTSA, and KRA have all experienced attacks on their digital systems. Malware incidents reached 103 million in nine months. Public institutions hold population-scale data with security budgets built for a different era.
image:
  path: https://images.unsplash.com/photo-1451187580459-43490279c0fa?w=1200&h=500&fit=crop&q=80
  alt: National infrastructure network
---

## The Target Set Has Shifted

Ransomware operators optimise for one thing: the probability that the victim pays. That calculation favours organisations where downtime is intolerable and where security maturity lags behind operational dependence on digital systems.

Kenyan public institutions and utilities fit that profile precisely.

Kenya Power, Kenya Railways Corporation, and the National Transport and Safety Authority have all experienced attacks affecting their digital systems. Multiple Kenyan government websites were rendered inaccessible in a suspected coordinated attack. The Kenya Revenue Authority's official social media account was compromised, with the public warned against fraudulent posts.

Communications Authority data recorded malicious software attacks reaching **103 million in the nine months to September 2025**, up from 99 million in the same period the previous year.

---

## Why Public Sector Is Exposed

**Legacy systems with long replacement cycles.** Government systems are procured on multi-year cycles and often run well past vendor support end-of-life. Unsupported software does not receive security patches.

**Procurement timelines misaligned with threat velocity.** A vulnerability disclosed today may be exploited within 48 hours. A procurement process to acquire a patching solution takes months.

**Population-scale data.** Government databases contain national ID numbers, tax records, vehicle registrations, land titles, and health records for millions of people. The extortion leverage from threatening to publish that data is enormous.

**Operational intolerance for downtime.** A utility that cannot bill, a transport authority that cannot issue licences, a revenue authority that cannot process returns. The pressure to restore service quickly is the pressure that makes payment attractive.

**Constrained security budgets.** Security competes with service delivery for funding in an environment where the visible priorities are always operational.

---

## The Modern Ransomware Pattern

Understanding the current attack model matters because the defensive priorities have shifted.

Encryption is no longer the primary leverage. The dominant model is:

**Access, dwell, exfiltrate, then encrypt.** Attackers spend days to weeks inside the network before deploying any payload. During that period they map the environment, escalate to domain administrator, identify and corrupt backups, and exfiltrate the most sensitive data they can find.

By the time encryption fires, the damage is already done. The organisation restores from backup, discovers the backups were targeted first, and then receives a ransom demand based on the exfiltrated data rather than the encrypted systems.

Some groups have abandoned encryption entirely. Data theft and extortion alone are quieter, faster, and equally effective.

---

## Detection Priorities During the Dwell Period

The dwell period is your detection window. These are the highest-fidelity signals.

### Shadow Copy Deletion

The clearest pre-ransomware indicator available. Alert immediately, escalate as a P1.

```
Process command line contains:
  vssadmin delete shadows
  wmic shadowcopy delete
  bcdedit /set recoveryenabled No
  wbadmin delete catalog
```

There is no legitimate business reason for these commands to run on a production server. Any occurrence is an incident.

### Backup System Interference

Alert on service stop events for backup agents, deletion of backup jobs, modification of backup retention policies, and authentication to backup management consoles from unusual accounts.

Attackers target backups deliberately and early. Your backup infrastructure should have its own alerting, separate credentials, and ideally its own authentication domain.

### Credential Dumping

Windows Event ID 4688 with suspicious process names, LSASS memory access from non-standard processes, and known tooling signatures.

```
EventID: 4688
NewProcessName contains: mimikatz, procdump, comsvcs.dll MiniDump
```

### Lateral Movement

- Service installation events (Event ID 7045) with randomly generated service names, the PsExec signature
- WMI process creation from remote hosts
- RDP connections between workstations, which almost never happens legitimately
- SMB connections to administrative shares from non-administrative hosts

### Security Tool Tampering

Any attempt to stop, disable, or uninstall antivirus or EDR agents. Attackers do this immediately before deploying the payload.

### Data Staging

Large archives being created in unusual directories, particularly `.7z`, `.zip`, or `.rar` files in temp folders, followed by large outbound transfers to cloud storage services or unfamiliar IP addresses.

---

## Recovery Architecture

Detection buys you time. Recovery capability determines whether you have to negotiate.

**Immutable backups.** Backups that cannot be modified or deleted for a defined retention period, even by an administrator account. This is the single control that defeats backup-targeting.

**Offline or air-gapped copies.** At least one backup copy that is not network-reachable from production.

**Tested restoration.** A backup that has never been restored is a hypothesis, not a control. Test full restoration of critical systems quarterly and document the actual recovery time.

**Segmented backup credentials.** Backup infrastructure should not authenticate against the same Active Directory as production. Domain admin compromise should not equal backup compromise.

**Documented, offline incident response plan.** If your IR plan lives on the network that just got encrypted, you do not have an IR plan. Print it. Distribute it. Include out-of-band contact details for the response team, KE-CIRT/CC, and legal counsel.

---

## The Regulatory Dimension

Kenya's Data Protection Act requires notification to the Office of the Data Protection Commissioner where a breach poses a real risk of harm to data subjects. A ransomware incident involving exfiltration of personal data triggers that obligation.

Institutions should establish the notification decision process before an incident, not during one. Who decides. What the threshold is. What the timeline is. Who drafts the notification. These questions take days to resolve under pressure and hours to resolve in advance.

---

## Key Takeaways

- Kenya Power, Kenya Railways, NTSA, and KRA have all experienced attacks on digital systems, with malware incidents reaching 103 million in nine months.
- Public institutions are attractive targets due to legacy systems, population-scale data holdings, downtime intolerance, and constrained security budgets.
- Modern ransomware exfiltrates before encrypting and targets backups first. Backup alone is no longer a sufficient defence.
- The detection window is the dwell period. Shadow copy deletion, backup tampering, credential dumping, and security tool disabling are the highest-fidelity signals.
- Immutable backups with segmented credentials are the control that most directly removes the attacker's leverage.

*Written by Glenn Ongalo | Nairobi, Kenya*
