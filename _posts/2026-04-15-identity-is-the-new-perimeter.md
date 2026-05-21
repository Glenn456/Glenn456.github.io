---
title: "Identity Is the New Perimeter: Understanding Credential-Based Attacks"
date: 2026-04-15 09:00:00 +0300
categories: [Cybersecurity, Threat Intelligence]
tags: [identity, credentials, account takeover, blue team, soc, mfa, active directory]
description: Stolen credentials are now the leading cause of breaches. Understanding how attackers abuse identity and what defenders can do about it is one of the most important skills in modern security operations.
---

## Introduction

If you had to pick the single most exploited weakness in enterprise security today, it would not be a zero-day vulnerability or a sophisticated malware strain. It would be a username and a password.

Credential-based attacks are the dominant initial access technique in 2026. Attackers do not need to break down the door when they can walk in with a stolen key.

---

## The Identity Attack Lifecycle

Understanding how credential-based attacks unfold helps you build detection across multiple stages.

### Phase 1: Credential Acquisition

Attackers obtain credentials through several routes:

- **Phishing** -- The most common. A convincing email or fake login page harvests credentials directly.
- **Credential stuffing** -- Using leaked username/password pairs from previous breaches against new targets. Given that billions of credentials from past breaches are freely available, this works more often than it should.
- **Infostealer malware** -- Malware like RedLine and Lumma Stealer silently harvest saved browser credentials and session cookies from infected machines. The stolen data is then sold in bulk on criminal marketplaces.
- **Password spraying** -- Trying a small set of common passwords against a large number of accounts to avoid lockout thresholds.
- **MFA fatigue / push bombing** -- Repeatedly sending MFA push notifications until an exhausted user approves one.

### Phase 2: Access and Persistence

Once inside, attackers move quickly to establish persistence before credentials are rotated:

- Creating new accounts with admin privileges.
- Enrolling new MFA devices to maintain access even after the original credential is reset.
- Harvesting session tokens from browser memory or stored cookies to bypass MFA entirely.

### Phase 3: Lateral Movement and Privilege Escalation

With initial access established, attackers target higher-privilege accounts:

- **Pass-the-Hash** -- Using harvested NTLM hashes to authenticate without knowing the plaintext password.
- **Kerberoasting** -- Requesting Kerberos tickets for service accounts and cracking them offline to recover plaintext passwords.
- **DCSync** -- Mimicking a domain controller to replicate Active Directory credentials.

---

## Detection Priorities for SOC Analysts

Identity attacks leave specific footprints. Build detection around these signals:

**Authentication anomalies:**
- Logins from unusual countries or IP ranges (especially within minutes of a successful domestic login -- "impossible travel").
- Multiple failed login attempts followed by a success (credential stuffing pattern).
- Authentication via legacy protocols like Basic Auth or NTLM when modern protocols are expected.

**MFA abuse:**
- A high volume of MFA push notifications sent to a single user in a short period (push bombing indicator).
- MFA method changes, especially adding a new authenticator app or phone number.
- Successful logins where MFA was bypassed due to a "trusted device" exemption from an unfamiliar device.

**Privilege escalation in Active Directory:**
- New accounts created in privileged groups (Domain Admins, Enterprise Admins).
- DCSync activity from a non-domain-controller machine -- Windows Event ID 4662 with specific object access rights.
- Kerberoasting: abnormally high volume of Kerberos service ticket requests (Event ID 4769) for accounts with high-value SPNs.

---

## Key Takeaways

- Credentials are the number one initial access vector. Identity security is not a nice-to-have.
- Phishing, credential stuffing, infostealer malware, and MFA fatigue are the primary collection methods.
- Detection must focus on authentication anomalies, MFA abuse patterns, and Active Directory privilege changes.
- Strong MFA (hardware keys or number-matching authenticators) remains one of the highest-value defensive controls.

An attacker with valid credentials is an attacker wearing a disguise. Your job is to spot when the disguise does not fit.
