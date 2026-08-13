---
title: "The Threat Kenyan Banks Do Not Want to Name: Insider Fraud"
date: 2026-07-26 09:00:00 +0300
categories: [Cybersecurity, Kenya]
tags: [insider threat, kenya, banking, fraud, aml, detection engineering, ueba, soc, blue team]
description: The Central Bank of Kenya reports rising cyber fraud. Bank staff, investigators, and former compliance officers say most losses are inside jobs. When institutions label insider theft as a cyberattack, they build the wrong defences.
image:
  path: https://images.unsplash.com/photo-1497366216548-37526070297c?w=1200&h=500&fit=crop&q=80
  alt: Empty office desk representing insider access
---

## A Reporting Problem, Not Just a Security Problem

The Central Bank of Kenya's Financial Sector Stability Report documented 353 cyber fraud cases in the banking sector in 2024, up from 153 the year before, with losses of KES 1.5 billion.

Those are the official numbers. But accounts from victims, bank staff, and law enforcement investigators suggest a different picture of what is actually happening.

An investigation published by TechCabal in September 2025 documented interviews with a former bank compliance officer and a Banking Fraud Investigations Unit investigator describing a shadow economy operating out of Nairobi neighbourhoods including Utawala and Ruiru, built on mobile banking fraud that depends on insider access.

The investigator described schemes that do not fit clean categories. A phishing text may be the entry point, but a bank teller passes on stolen customer data, funds are laundered through mobile money, and police officers are paid to look the other way. Each stage blurs the line between cyberattack, insider theft, and organised racketeering.

---

## Why Institutions Prefer the "Hacker" Narrative

The former compliance officer identified the incentive clearly. Banks anxious to reassure shareholders and depositors frame losses as cyber threats even when investigations point to human hands inside the institution.

The reasons are straightforward. A cyberattack is an external event. It suggests the institution was targeted by a sophisticated adversary. Insider fraud suggests failures of hiring, supervision, access control, and culture. One narrative protects the brand. The other invites regulatory scrutiny and reputational damage.

The consequence is that resources get allocated to the wrong problem. If your loss reports say "cyberattack" when the root cause is a teller selling customer data, you will spend your security budget on perimeter tools that cannot detect the actual threat.

---

## What Insider Threat Looks Like in Kenyan Banking

**Data exfiltration by frontline staff.** Tellers, customer service agents, and back-office staff have legitimate access to customer records including account numbers, balances, ID numbers, phone numbers, and transaction histories. This data is directly monetisable to SIM swap and social engineering operations. Police raids on fraud syndicates in Bomet and elsewhere have repeatedly recovered exercise books containing exactly this kind of information: customer M-PESA balances, Fuliza limits, and KCB M-PESA loan limits.

**Transaction manipulation.** Staff with authority to reverse, adjust, or approve transactions can move funds and cover the trail. Small amounts across many accounts are harder to detect than one large theft.

**Access provisioning abuse.** Employees who can create or modify user accounts can grant themselves or accomplices elevated permissions, then remove the evidence.

**Collusion with external actors.** The most damaging pattern. An insider provides the data and the timing, an external actor executes the fraud, and the money moves through mobile money into cash. The insider never touches the funds directly, which makes attribution difficult.

**Third-party contractor access.** A reported breach involving compromised contractors cost a Kenyan bank over KSh 517 million. Contractors and vendors frequently receive broad system access with minimal monitoring.

---

## Detection Engineering for Insider Threat

Insider threat detection is fundamentally different from external threat detection. There is no perimeter breach to catch. The user is authenticated, authorised, and using systems exactly as designed. What changes is the pattern.

### Build a Baseline First

You cannot detect anomalous behaviour without knowing what normal looks like. For every role in the institution, establish:

- Typical volume of customer records accessed per shift
- Normal working hours and access locations
- Standard set of systems and functions used
- Typical transaction values and approval frequencies

### High-Value Detection Rules

**Bulk record access.** A teller accessing 200 customer records in an hour is not doing their job. Set a threshold based on role baseline and alert on any user exceeding it.

**Out-of-hours access.** Access to core banking systems outside the user's normal shift pattern, particularly access to customer data rather than transaction processing.

**Access to accounts with no business relationship.** If a teller in a Mombasa branch is pulling records for customers who only transact in Kisumu, that requires justification.

**Dormant account activity.** Fraudsters favour dormant accounts because customers do not notice. Alert on any staff-initiated activity on accounts that have been inactive for an extended period.

**Post-resignation access.** Access patterns often change in the weeks before an employee leaves. Elevated monitoring for users who have given notice is standard practice in mature programmes.

**Reversal and adjustment patterns.** Track reversal frequency per user. A user with significantly higher reversal rates than peers in the same role warrants review.

**Report generation and export.** Any bulk data export, report download, or query returning large result sets should be logged, attributed, and reviewed.

### UEBA Where You Can Afford It

User and Entity Behaviour Analytics platforms build statistical models of individual user behaviour and flag deviations. They are expensive, but the underlying logic can be replicated with SIEM correlation rules and scheduled queries for institutions that cannot justify the licence cost.

The core principle is the same: measure each user against their own historical baseline and their peer group, then alert on deviation.

---

## Controls Beyond Detection

**Least privilege, enforced and reviewed.** Most banking staff have accumulated permissions over years of role changes. Quarterly access recertification, where managers must actively confirm each report's permissions are still required, removes accumulated privilege.

**Separation of duties.** No single user should be able to create a beneficiary, approve a transfer, and reverse a transaction. Enforce this in system design, not policy documents.

**Mandatory leave.** Two consecutive weeks of enforced leave annually is a long-standing banking control because ongoing fraud schemes often require continuous attention to maintain. It surfaces schemes that depend on daily intervention.

**Vendor access governance.** Every contractor and third party with system access should have time-limited credentials, defined scope, and the same monitoring applied to internal staff. The KSh 517 million contractor breach was an access governance failure.

**Whistleblower channels that work.** Staff frequently know about fraud before controls detect it. An anonymous reporting channel with credible protection is a detection mechanism, not just a compliance box.

---

## Key Takeaways

- CBK reported 353 banking cyber fraud cases in 2024 with KES 1.5 billion in losses, but investigators and bank staff indicate a substantial share involves insider participation.
- Institutions have an incentive to label insider fraud as external cyberattack, which misdirects security investment toward perimeter controls that cannot address the actual threat.
- The dominant Kenyan pattern is collusion: insiders supply data and timing, external actors execute, funds launder through mobile money.
- Detection requires role-based baselining and behavioural rules, not signature-based tooling. Bulk record access, out-of-hours activity, and dormant account manipulation are the highest-value signals.
- Controls that reliably surface insider schemes: quarterly access recertification, enforced separation of duties, mandatory leave, and vendor access governance.

*Written by Glenn Ongalo | Nairobi, Kenya*
