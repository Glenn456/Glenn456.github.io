---
title: "The KSh 517 Million Lesson: Third-Party Access Is Your Attack Surface"
date: 2026-07-27 09:00:00 +0300
categories: [Cybersecurity, Kenya]
tags: [third party risk, supply chain, kenya, banking, vendor management, access control, soc, blue team]
description: A reported breach involving compromised contractors cost a Kenyan bank over KSh 517 million. Third-party and supply chain breaches have quadrupled in five years globally. Most organisations cannot enumerate who has access to their systems.
image:
  path: https://images.unsplash.com/photo-1504868584819-f8e8b4b6d7e3?w=1200&q=80
  alt: Vendor access and supply chain security
---

## The Access You Forgot You Granted

A reported breach involving compromised contractors cost a Kenyan bank over KSh 517 million, highlighting weaknesses in third-party access control.

That figure is worth sitting with. Half a billion shillings, through access the institution granted deliberately, to parties it selected, for purposes it approved.

IBM X-Force reported that supply chain and third-party breaches have quadrupled over the past five years. It is among the fastest-growing attack vectors globally, and it is structurally significant in Kenya's deeply integrated financial ecosystem.

---

## Who Actually Has Access

Ask most Kenyan organisations for a complete list of third parties with access to their systems and the answer takes weeks to produce, if it can be produced at all.

The categories that get overlooked:

**Core system vendors** with permanent remote support access, often through a shared account, sometimes with credentials that have not changed since implementation.

**Implementation contractors** who completed a project two years ago and whose accounts were never disabled.

**Managed service providers** with domain administrator access for infrastructure support.

**SaaS applications** with OAuth integrations granting read or write access to email, files, or calendar data. Every integration a user approves is a third party with access.

**Payment and integration partners** connected via API, often with tokens that never expire.

**Cleaning, maintenance, and facilities staff** with physical access to server rooms and workstations.

**Auditors and consultants** granted read access for an engagement that ended months ago.

**Recruitment and HR platforms** holding employee personal data.

Each is a potential entry point, and collectively they represent an attack surface that sits outside most organisations' security monitoring entirely.

---

## The Attack Patterns

**Compromised vendor credentials.** The attacker breaches the vendor, harvests credentials for the vendor's customers, and uses legitimate access to enter each one. The customer sees a normal support login.

**Malicious or compromised software updates.** The vendor's build pipeline is compromised, and the malicious update arrives signed and trusted. This is the SolarWinds pattern, and the TanStack npm attack demonstrated it remains effective in 2026.

**Middleware exploitation.** The Uganda Pegasus Technologies breach exploited middleware linking banks to mobile money, siphoning approximately USD 3 million using around 2,000 SIM cards. The banks themselves were not breached. The layer connecting them was.

**Insider access at the vendor.** A vendor employee with access to multiple customer environments, misusing it.

**Fourth-party risk.** Your vendor's vendor. Most organisations have no visibility into their suppliers' supply chains.

---

## Building a Third-Party Security Programme

### Start With the Inventory

Before any assessment or contractual work, enumerate. For every third party:

- What systems and data can they access
- What is the access mechanism: VPN, direct connection, API, SaaS integration, physical
- Which accounts belong to them
- Who inside the organisation owns the relationship
- What is the contract status
- When was access last reviewed

Run a technical discovery alongside the business inventory. Query your identity provider for accounts with external domain email addresses. Review OAuth application consents. Check VPN and remote access logs for connections from vendor IP ranges. You will find access nobody remembered granting.

### Tier by Risk

Not every vendor needs the same scrutiny. Tier by two dimensions: sensitivity of data or systems accessed, and criticality to operations.

**Tier 1:** Access to production financial systems, customer PII at scale, or ability to affect service availability. Full security assessment, annual review, contractual security obligations, incident notification requirements.

**Tier 2:** Access to internal systems or limited personal data. Security questionnaire, biennial review, standard contractual terms.

**Tier 3:** No access to systems or sensitive data. Standard terms only.

Most organisations have far fewer Tier 1 vendors than they expect, which makes the assessment burden manageable.

### Contractual Requirements

For Tier 1 vendors, the contract should require:

- Notification of security incidents affecting your data within a defined period, ideally 24 to 48 hours
- Right to audit, or provision of independent assessment reports
- Defined patching and vulnerability management commitments
- Sub-processor disclosure and approval requirements
- Data location and cross-border transfer terms compliant with the Data Protection Act
- Defined data return and destruction obligations at contract end
- Named security contact with escalation path

### Technical Controls

Contracts do not prevent breaches. Controls do.

**Named individual accounts, never shared.** If four vendor engineers need access, that is four accounts, each attributable. Shared accounts make attribution impossible and offboarding unreliable.

**Time-bound access.** Vendor access should expire by default and require renewal. Standing permanent access is the exception requiring justification, not the norm.

**Just-in-time elevation.** For maintenance requiring elevated privilege, grant it for the maintenance window and revoke automatically.

**Network segmentation.** Vendor access should reach only the specific systems required, enforced at the network layer.

**Session recording** for Tier 1 vendor access to critical systems.

**Dedicated monitoring.** Vendor accounts should have their own alerting: access outside agreed hours, access to systems outside their defined scope, unusual data volumes, and authentication from unexpected locations.

### Offboarding Discipline

The failure point in almost every third-party access review is offboarding. Project ends, contract expires, engagement concludes, and access persists.

Build offboarding into the contract lifecycle. When a contract ends or a project closes, access revocation should be a required step with a named owner and evidence of completion.

---

## Key Takeaways

- A single third-party contractor compromise cost a Kenyan bank over KSh 517 million. Supply chain breaches have quadrupled globally in five years.
- Most organisations cannot enumerate who has access to their systems, and technical discovery consistently finds access nobody remembered granting.
- The overlooked categories are OAuth SaaS integrations, dormant contractor accounts, and permanent vendor support access through shared credentials.
- Tier vendors by data sensitivity and operational criticality. The Tier 1 population is usually smaller than expected, making thorough assessment feasible.
- The controls that matter are technical: named accounts, time-bound access, network segmentation, and dedicated monitoring for vendor activity.

*Written by Glenn Ongalo | Nairobi, Kenya*
