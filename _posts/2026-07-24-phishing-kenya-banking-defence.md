---
title: "Phishing in Kenya: Why It Still Works and How to Actually Stop It"
date: 2026-07-24 09:00:00 +0300
categories: [Cybersecurity, Kenya]
tags: [phishing, smishing, kenya, banking, dmarc, email security, blue team, soc, detection engineering]
description: Bank-related phishing accounts for 53.75% of all phishing attacks in Africa, the highest of any region globally. Kenyan banks lost KSh 1.59 billion to fraud in 2024. Here is the anatomy of the attack and the concrete controls a security engineer can deploy against it.
image:
  path: https://images.unsplash.com/photo-1556742049-0cfed4f6a45d?w=1200&h=500&fit=crop&q=80
  alt: Banking notification arriving on a phone
---

## Africa Leads the World in Bank Phishing

Kaspersky's 2026 analysis of global phishing patterns found something specific about this continent. In the Middle East, e-commerce phishing dominates at 85.8% of attacks. In Latin America, Asia-Pacific, and Europe, phishing is distributed fairly evenly across sectors.

In Africa, **bank-related phishing leads at 53.75%**, the highest concentration of any region worldwide.

That is not a coincidence. It is a direct reflection of where the money is and where the controls are weakest.

---

## The Kenyan Numbers

The Central Bank of Kenya's Financial Sector Stability Report documented cyber fraud cases in the banking sector more than doubling in 2024, rising from 153 to 353 reported incidents. The amount exposed increased to KES 1.9 billion. Actual losses nearly quadrupled to KES 1.5 billion.

Mobile banking was the hardest hit channel, with criminals siphoning KSh 810.68 million, a 344% increase from KSh 182.41 million the prior year. That single channel accounted for more than half of all funds stolen from Kenyan banks.

The Communications Authority attributed the surge to three factors: inadequate system patching, limited user awareness of threat vectors including phishing and social engineering, and the growing adoption of AI-driven attacks.

---

## The Kenyan Phishing Playbook

Attacks targeting Kenyan bank customers follow recognisable patterns. Understanding them is the first step to building detection.

**Smishing (SMS phishing) is the dominant vector.** Kenya is a mobile-first market. Email penetration is lower than SMS penetration by an order of magnitude. Attackers send SMS messages impersonating M-PESA, Equity, KCB, or Co-operative Bank, typically claiming a failed transaction, a suspended account, or an unexpected credit that needs confirmation.

**Late-night targeting.** CBK data shows thefts concentrate on Friday and Saturday nights, targeting people who are out and less cautious. Millennials are the most affected demographic. This is deliberate behavioural targeting, not random.

**The reversal scam.** The victim receives a fake M-PESA confirmation SMS showing money received. Minutes later, a caller claims they sent it by mistake and asks for a reversal. The original message was spoofed. The victim sends real money back for funds they never received.

**Fake customer care numbers.** Attackers buy Google Ads or seed fake numbers in online listings for bank and telco customer care. Victims searching for help call the attacker directly and hand over credentials during what feels like a legitimate support call.

**Credential harvesting portals.** Cloned login pages for Kenyan bank portals, hosted on lookalike domains, often with valid TLS certificates from free certificate authorities. The padlock icon no longer signals safety.

---

## Detection and Mitigation for Security Engineers

This is the practical section. These are controls you can implement.

### Email Authentication: DMARC, SPF, DKIM

If your institution's domain does not have a DMARC policy set to `p=reject`, attackers can spoof your domain in phishing emails and your customers have no technical protection.

```
_dmarc.yourbank.co.ke  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@yourbank.co.ke; pct=100"
```

Start at `p=none` to collect reports, review the aggregate data for legitimate senders you may have missed, move to `p=quarantine`, then to `p=reject`. Most Kenyan financial institutions are still at `p=none` or have no DMARC record at all. This is one of the highest-value, lowest-cost controls available.

### Domain Monitoring and Takedown

Register a monitoring feed for newly registered domains containing your brand name or common typosquats. Certificate Transparency logs are free and searchable. Any new certificate issued for a domain resembling yours is a potential phishing infrastructure signal, often visible days before the campaign launches.

```bash
# Query crt.sh for certificates matching your brand
curl -s "https://crt.sh/?q=%25yourbank%25&output=json" | jq '.[].name_value' | sort -u
```

Build this into a scheduled job. Alert on new entries.

### SMS Sender ID Protection

Work with the Communications Authority and mobile network operators to register and protect your alphanumeric sender IDs. Unregistered sender IDs can be spoofed. Registered ones cannot be used by third parties on Kenyan networks.

### Behavioural Detection on Transaction Patterns

Phishing succeeds at the credential level, but the loss happens at the transaction level. Build detection there:

- Transactions initiated within 15 minutes of a password or PIN change
- First-time beneficiary transfers above a value threshold
- Multiple failed authentication attempts followed by a success, then immediate high-value transfer
- Transactions from a device fingerprint never previously associated with the account
- Velocity anomalies: three or more transfers to new beneficiaries within an hour

### SIM Swap Correlation

Safaricom provides a SIM-Swap Check API that lets banks query when a customer's SIM was last swapped. If a SIM was swapped within the last 24 to 72 hours, any high-value transaction on that account should be held for out-of-band verification.

If your institution is not consuming this API, that is a gap worth closing this quarter. Six banks had integrated it as of 2023. In a market where SIM swap drives a large share of mobile banking fraud, that number should be every bank.

### User-Reported Phishing as a Detection Signal

Give customers a single, well-publicised channel to report suspicious messages. Then treat every report as a detection event, not just a support ticket. One customer reporting a smishing campaign gives you the sender ID, the malicious URL, and the message template, all of which feed directly into blocking rules and threat intelligence sharing.

---

## What Awareness Training Should Actually Teach

Traditional phishing awareness training teaches people to spot bad grammar and suspicious links. AI-generated phishing has made that advice obsolete.

Teach behaviour instead of detection:

- Never act on an inbound message that creates urgency about money. Hang up, close the message, and contact the institution using a number you already have.
- No legitimate bank or telco will ever ask for your PIN, password, or OTP. Not once. Not for verification. Not ever.
- An unexpected credit is not free money. It is a scam setup.
- If you did not initiate an authentication prompt, do not approve it.

The goal is not teaching people to identify a fake message. It is teaching them a rule that holds even when the message is perfect.

---

## Key Takeaways

- Africa has the world's highest concentration of bank-focused phishing at 53.75% of all phishing attacks in the region.
- Kenyan banks lost KSh 1.59 billion to fraud in 2024, with mobile banking accounting for over half at KSh 810.68 million, a 344% year-on-year increase.
- Smishing dominates in Kenya because the market is mobile-first. Email-focused controls alone will not address the primary vector.
- Highest-value engineering controls: DMARC at p=reject, Certificate Transparency monitoring for lookalike domains, SIM-Swap Check API integration, and transaction-layer behavioural detection.
- Awareness training must teach behavioural rules, not detection heuristics. Grammar-based detection is dead.

*Written by Glenn Ongalo | Nairobi, Kenya*
