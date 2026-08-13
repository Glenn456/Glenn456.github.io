---
title: "Business Email Compromise: The Quiet Millions Leaving Kenyan Companies"
date: 2026-08-07 09:00:00 +0300
categories: [Cybersecurity, Kenya]
tags: [bec, email security, kenya, fraud, dmarc, detection engineering, soc, blue team, incident response]
description: BEC does not involve malware, exploits, or technical intrusion. It involves an email, a wire transfer, and a process that permitted both. It is one of the highest-loss attack categories affecting Kenyan businesses and one of the most preventable.
image:
  path: https://images.unsplash.com/photo-1516321318423-f06f85e504b3?w=1200&q=80
  alt: Business email compromise and wire transfer fraud
---

## No Malware Required

Business Email Compromise is a process failure wearing a cybersecurity costume.

There is no exploit. No malware. Often no technical compromise at all. An attacker sends an email, someone authorises a payment, and money leaves the organisation. Once funds have moved internationally, recovery becomes extremely difficult.

For Kenyan businesses engaged in import, export, or any cross-border trade, this is one of the highest-loss threat categories in operation.

---

## The Four Variants

### CEO Fraud

The attacker impersonates a senior executive, usually via a lookalike domain or a display name spoof, and instructs a finance staff member to make an urgent confidential payment.

The email typically arrives when the executive is known to be travelling or unreachable, emphasises confidentiality to prevent verification, and creates time pressure.

### Vendor Invoice Fraud

The highest-value variant. The attacker compromises or spoofs a supplier's email account and sends an invoice with updated bank details, claiming the supplier has changed banks.

The invoice is real. The relationship is real. The amount matches an expected payment. Only the account number is wrong. Payments proceed because everything checks out except the one detail nobody verifies.

For Kenyan importers paying overseas suppliers, this variant has produced very large single losses.

### Payroll Diversion

The attacker impersonates an employee and requests a change of salary payment details to a new account. Individually smaller amounts, but often undetected for a full pay cycle.

### Attorney or Regulator Impersonation

The attacker claims to represent a law firm handling a confidential transaction or a regulatory body requiring an urgent payment. Authority and confidentiality suppress normal verification.

---

## Why It Works in the Kenyan Context

**Hierarchy and deference.** In many Kenyan corporate cultures, questioning an instruction from a senior executive is uncomfortable. Attackers exploit this directly. The confidentiality framing gives the recipient a reason not to verify with anyone.

**Email as the primary business channel.** Cross-border trade runs on email. Invoices, shipping documents, and payment instructions all arrive by email, which normalises the channel for financial instructions.

**Limited email authentication adoption.** Many Kenyan organisations have not implemented DMARC, SPF, and DKIM at enforcement level, which means their domains can be spoofed and their partners have no technical protection.

**Correspondent banking delays.** International wire transfers pass through correspondent banks. By the time fraud is identified, funds have typically moved through several institutions and jurisdictions.

---

## Detection Engineering

### Email Gateway Rules

**External sender with internal display name.** Alert on any inbound email where the display name matches an internal executive but the sending domain is external. This single rule catches most CEO fraud attempts.

**Lookalike domain detection.** Monitor for newly registered domains resembling yours and your key suppliers. Common substitutions: `rn` for `m`, `l` for `I`, `0` for `o`, added or dropped hyphens, alternative TLDs.

**Reply-to mismatch.** Alert when the reply-to address differs from the from address on inbound mail. Legitimate business correspondence rarely does this.

**External email banner.** Prepend a visible banner to every email originating outside the organisation. Simple, unglamorous, and effective.

### Mailbox Rule Monitoring

When an attacker compromises a mailbox, one of the first actions is creating an inbox rule that auto-deletes or auto-forwards messages containing keywords like "invoice," "payment," or "bank," so the legitimate user never sees the correspondence.

Alert on any new inbox rule that forwards externally, deletes on receipt, or moves messages to obscure folders.

In Microsoft 365:
```
Search-UnifiedAuditLog -Operations "New-InboxRule","Set-InboxRule" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date)
```

Run this weekly. Review every result.

### Authentication Anomalies

- Impossible travel: successful authentications from geographically distant locations within an implausible timeframe
- Legacy authentication protocol usage, which bypasses MFA
- New mail client registrations
- OAuth application consents granted to unfamiliar applications

### Outbound Monitoring

Compromised accounts send mail. Alert on unusual outbound volume, mail sent to large numbers of external recipients, or messages sent outside the user's normal hours.

---

## The Controls That Actually Stop It

Detection helps. Process controls prevent.

**Callback verification on every bank detail change.** No exceptions, no seniority override. The call must use a number from your own vendor master record, never a number provided in the email requesting the change.

Make this a system control. The payment should not be processable without a recorded verification.

**Dual authorisation above threshold.** Two independent approvers for any payment above a defined value, with the second approver required to confirm they independently verified the beneficiary details.

**New beneficiary cooling-off.** A mandatory delay, typically 24 to 48 hours, before a first payment to any new beneficiary account. This alone defeats the urgency mechanism BEC depends on.

**Vendor master data governance.** Bank detail changes in the vendor master should require documented verification and should be performed by someone other than the person who processes payments.

**DMARC at p=reject.** Prevents your domain being spoofed against your partners and customers.

**Confidentiality is a red flag, not a justification.** Train staff explicitly: any payment request that discourages verification is fraudulent until proven otherwise. Legitimate transactions survive verification.

---

## If It Happens

Speed determines recovery. Within the first hours:

1. Contact your bank immediately and request a recall. Recovery probability drops sharply after 24 hours.
2. Report to the Directorate of Criminal Investigations and to KE-CIRT/CC.
3. If funds went to a foreign account, ask your bank to initiate a SWIFT recall through the correspondent chain.
4. Preserve all email headers and audit logs before anything is deleted.
5. Assume mailbox compromise until proven otherwise. Reset credentials, revoke sessions, and audit inbox rules.

---

## Key Takeaways

- BEC requires no malware or technical exploitation. It exploits process gaps and organisational hierarchy.
- Vendor invoice fraud is the highest-value variant for Kenyan businesses engaged in cross-border trade.
- The highest-fidelity detection rules are external-sender-with-internal-display-name, reply-to mismatch, and new inbox rule creation.
- The controls that prevent it are procedural: callback verification using independently sourced numbers, dual authorisation, and new beneficiary cooling-off periods.
- Confidentiality framing in a payment request should be treated as an indicator of fraud, not a reason to skip verification.

*Written by Glenn Ongalo | Nairobi, Kenya*
