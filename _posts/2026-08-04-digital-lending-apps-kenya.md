---
title: "195 Digital Lenders, One Shared Attack Surface"
date: 2026-08-04 09:00:00 +0300
categories: [Cybersecurity, Kenya]
tags: [kenya, fintech, digital lending, api security, data protection, cbk, odpc, mobile security, soc]
description: The CBK licensed 110 new digital credit providers in 2025, bringing the total to 195. Most are young organisations building on shared infrastructure with security programmes that have not scaled with their user base.
image:
  path: https://images.unsplash.com/photo-1563013544-824ae1b704d3?w=1200&q=80
  alt: Mobile lending application and financial data
---

## Growth Outpacing Governance

The Central Bank of Kenya licensed approximately 110 new digital credit providers in 2025, bringing the total number of licensed DCPs to 195.

That regulatory formalisation was necessary and overdue. It brought a previously unregulated sector under CBK supervision with requirements around pricing transparency, debt collection practices, and data handling.

What licensing did not do is establish a cybersecurity maturity baseline. A DCP can hold a valid licence and still have a security programme consisting of a firewall and hope.

---

## What Digital Lenders Actually Hold

The data concentration in this sector is significant and often underestimated.

A typical Kenyan digital lending application collects:

- National ID number and a photograph of the ID document
- Selfie for biometric verification
- Full M-PESA transaction history, often via API access granted at signup
- Phone contact list in some cases, historically used for debt collection pressure
- SMS message content, parsed for financial signals
- Device identifiers, location data, and installed application lists
- Employment and income information
- Next of kin and referee contact details

That is a comprehensive identity and financial profile on hundreds of thousands of Kenyans, sitting in the infrastructure of organisations that may have been founded three years ago.

For an attacker, a single DCP breach yields everything needed for large-scale identity fraud, SIM swap targeting, and social engineering against the victim's entire contact network.

---

## The Structural Vulnerabilities

### Shared Infrastructure Dependency

Most DCPs do not build their own core systems. They build on shared components: a core lending platform from a regional vendor, a credit scoring API, an identity verification service, an SMS gateway, and mobile money integration through Daraja or an aggregator.

That means a vulnerability in one widely used middleware provider creates exposure across a large portion of the sector simultaneously. This is the pattern that produced the Uganda Pegasus Technologies breach, where attackers exploited middleware linking banks to mobile wallets and siphoned approximately USD 3 million using around 2,000 SIM cards.

The same architecture exists in Kenya.

### Mobile Application Security

The lending product **is** the mobile app. Common weaknesses in this category:

**Hardcoded API keys and secrets in the APK.** Decompiling an Android application is trivial. Any credential embedded in the client is a public credential.

```bash
apktool d lender.apk -o output/
grep -rE "(api[_-]?key|secret|password|token)" output/ --include=*.smali --include=*.xml
```

**Absent certificate pinning.** Without pinning, an attacker on the same network can intercept and modify traffic between the app and the backend.

**Insecure local storage.** Session tokens, PII, or credentials written to SharedPreferences or SQLite without encryption.

**Weak or missing API authorisation.** The most common and most damaging. The app authenticates the user, but the backend API does not verify that the authenticated user owns the resource being requested. This is IDOR at scale, and in a lending context it exposes other customers' complete financial profiles.

### Over-Permissioned M-PESA API Access

Many DCPs request broad access to transaction history for credit scoring purposes. If that access token is compromised, the attacker inherits visibility into the customer's complete mobile money activity.

---

## Controls for Security Engineers in the Sector

### API Authorisation Testing as Standard Practice

Every endpoint that accepts an identifier must verify ownership server-side. Test it systematically:

Create two accounts. Authenticate as Account A. Enumerate every API call the application makes. Then, authenticated as Account B, replay each request substituting Account A's identifiers. Any successful response is a critical finding.

This test takes an afternoon and finds the most damaging class of vulnerability in the sector.

### Rate Limiting and Velocity Controls

The Pegasus attack pattern was high-frequency, low-value transactions through a middleware layer. Rate limiting per user, per device, and per IP, combined with velocity anomaly detection at the transaction layer, would have surfaced it.

Apply limits at:
- Authentication attempts per account and per IP
- Loan application submissions per device identifier
- Disbursement requests per account per time window
- API calls per authenticated session

### Data Minimisation

Under the Data Protection Act, collection must be adequate, relevant, and limited to what is necessary. Contact list access for debt collection is neither necessary nor lawful for the stated purpose of credit assessment.

Beyond compliance, data you do not hold cannot be breached. Every field removed from collection reduces breach impact.

### Certificate Pinning and Runtime Protection

Implement certificate pinning in the mobile application. Add root and jailbreak detection. Add basic anti-tampering checks. None of these are absolute defences, but each raises attacker cost meaningfully.

### Third-Party Security Assessment

Every vendor in the stack, the core platform, the scoring API, the identity provider, the SMS gateway, needs security review before integration and periodically after. Contractual security requirements, evidence of penetration testing, and incident notification obligations should be standard.

If a vendor cannot produce a recent penetration test report, that is an answer.

---

## The Regulatory Direction

The CBK's National Payments Strategy committed to developing API standards for the sector. The Office of the Data Protection Commissioner has been increasingly active in enforcement against digital lenders over data collection and debt collection practices.

The direction is clear: the compliance floor is rising. Organisations that build security capability now will meet future requirements without disruption. Organisations that wait will be doing it under regulatory pressure with less time and worse options.

---

## Key Takeaways

- Kenya has 195 licensed digital credit providers, most of them young organisations holding comprehensive identity and financial profiles on large user bases.
- Shared middleware and API dependencies mean a single vendor vulnerability creates sector-wide exposure, as demonstrated by the Uganda Pegasus breach.
- The dominant vulnerability class is broken API authorisation, where the backend fails to verify resource ownership after authenticating the user.
- Hardcoded secrets in APKs, absent certificate pinning, and insecure local storage are common in the sector and straightforward to test for.
- Data minimisation is both a compliance requirement and the most effective breach impact reduction available.

*Written by Glenn Ongalo | Nairobi, Kenya*
