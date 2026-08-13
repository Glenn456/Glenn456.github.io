---
title: "Kenya Regulated Crypto. Now the Security Bill Comes Due."
date: 2026-08-12 09:00:00 +0300
categories: [Cybersecurity, Kenya]
tags: [cryptocurrency, vasp, kenya, aml, ctf, wallet security, lazarus, compliance, blockchain, soc]
description: The Virtual Asset Service Providers Act came into force in November 2025, creating a licensed and therefore identifiable set of crypto businesses in Kenya. Regulation brings legitimacy. It also brings a defined target list.
image:
  path: https://images.unsplash.com/photo-1580894732444-8ecded7900cd?w=1200&q=80
  alt: Cryptocurrency security and digital asset custody
---

## Regulation Creates a Target List

Kenya's Virtual Asset Service Providers Act came into force in November 2025, establishing a licensing framework for cryptocurrency exchanges, custodians, and related businesses, with mandatory AML and CTF controls.

Kenya is among Africa's leading cryptocurrency adoption markets alongside South Africa, Nigeria, and Egypt. Formalising the sector was necessary for consumer protection and for addressing the concerns that contributed to Kenya's FATF grey-listing.

It also produced a public register of organisations holding digital assets.

For threat actors who specialise in cryptocurrency theft, particularly DPRK-linked groups whose operations are assessed to fund state programmes, a licensed VASP register is a target list with regulatory validation of which entities hold meaningful assets.

---

## Why Crypto Businesses Face a Different Threat Model

**Irreversibility.** A fraudulent bank transfer can sometimes be recalled. A blockchain transaction cannot. Once assets move, recovery depends on the receiving exchange freezing them, which requires speed and cooperation that frequently do not materialise.

**Bearer instrument properties.** Control of the private key is control of the asset. There is no account holder verification, no chargeback, no dispute process. Key compromise equals total loss.

**Attribution difficulty.** Mixing services, chain hopping, and privacy coins complicate tracing, though blockchain analytics have improved substantially.

**State actor interest.** UN Panel of Experts assessments have attributed billions in cryptocurrency theft to DPRK-linked groups. These are well-resourced adversaries with sustained campaigns and considerable patience, not opportunistic criminals.

**Developer-targeted supply chain attacks.** Lazarus Group campaigns have specifically targeted crypto and fintech organisations through malicious npm packages, with Kenya named among the confirmed target countries alongside the UK, Spain, Nigeria, and Qatar. The malware families identified included BeaverTail, an infostealer targeting browser credentials and wallet data, and InvisibleFerret, a persistent backdoor.

---

## Custody Architecture

For any VASP, custody design is the foundational security decision.

**Cold storage majority.** The substantial majority of customer assets should be in offline storage requiring physical access and multi-party authorisation to move. Only operational liquidity sits in hot wallets.

**Multi-signature or MPC.** No single key should be able to move significant value. Multi-signature schemes requiring m-of-n approvals, or multi-party computation where the key is never fully assembled in one place, remove the single point of compromise.

**Geographic and organisational key distribution.** Key holders in different physical locations, ideally in different reporting lines, so that neither a physical incident nor a single compromised individual can produce a loss.

**Withdrawal allowlisting with time delays.** New withdrawal addresses subject to a mandatory delay before first use, typically 24 to 48 hours, with notification to the account holder through a separate channel.

**Withdrawal velocity limits** at the account and platform level, with automatic halt on threshold breach pending manual review.

**Documented and tested key recovery.** Key loss is as damaging as key theft. Recovery procedures need to exist, be documented, and be tested, without creating a recovery path that is itself an attack vector.

---

## Developer and Build Security

Given that supply chain attacks through developer infrastructure are a confirmed technique against this sector, build security deserves specific attention.

**Dependency integrity verification.** Lock files with integrity hashes. Verified package sources. Software composition analysis scanning every build for known-vulnerable and newly published suspicious packages.

**Isolated build environments.** Build systems should not have access to production keys, customer data, or treasury systems. A compromised build pipeline should not equal a compromised treasury.

**Code review with security focus** on anything touching key handling, transaction construction, or withdrawal logic. Two-person review minimum, with no self-approval.

**Developer endpoint hardening.** Developer machines are the initial target in these campaigns. Full disk encryption, EDR, restricted local administrator rights, and separate accounts for development and privileged operations.

**Package installation controls.** Consider an internal package registry that mirrors approved dependencies rather than pulling directly from public registries, with new packages subject to review before approval.

---

## AML and CTF as Security Function

Under VASPA, licensed providers carry AML and CTF obligations. These are usually framed as compliance requirements. They are also security controls, and treating them as such improves both functions.

**Transaction monitoring against sanctioned and flagged addresses.** Blockchain analytics providers maintain address lists linked to sanctioned entities, ransomware payments, and known theft proceeds. Screening incoming and outgoing transactions against these lists prevents your platform being used as a laundering conduit and gives early warning of association with criminal activity.

**Source of funds verification** at defined thresholds, which surfaces both money laundering and stolen asset placement.

**Suspicious activity reporting** to the Financial Reporting Centre, with defined internal thresholds and escalation.

**Travel rule compliance** for transfers above threshold, requiring originator and beneficiary information exchange between VASPs.

The connection to security is direct. DPRK-linked actors move stolen cryptocurrency through a sequence of conversions designed to appear as legitimate trading before reaching fiat. A VASP with weak transaction monitoring becomes an attractive conversion point for proceeds of attacks that occurred anywhere in the world. Strong AML controls protect the platform from becoming infrastructure for the very actors targeting it.

---

## Incident Response Specifics

Crypto incident response differs from conventional IR in important ways.

**Speed determines outcome entirely.** The window to freeze assets at a receiving exchange is measured in minutes to hours. Pre-establish contacts at major exchanges and with blockchain analytics providers before you need them.

**Blockchain forensics from the first minute.** Trace the outbound transaction immediately. Identify the receiving addresses. Determine whether they belong to a known exchange with a compliance function that can freeze.

**Public communication planning.** Crypto incidents become public quickly, often through on-chain observers before the platform discloses. Have a communication plan that does not require drafting under pressure.

**Regulatory notification.** VASPA obligations to the CBK, and Data Protection Act obligations to the ODPC where personal data is involved. Both timelines run from awareness, not from resolution.

---

## Key Takeaways

- VASPA licensing formalised Kenya's crypto sector and simultaneously produced a public register of organisations holding digital assets.
- DPRK-linked groups have run confirmed campaigns against crypto and fintech organisations with Kenya named among target countries, using npm supply chain attacks and custom malware.
- Custody architecture is the foundational control: cold storage majority, multi-signature or MPC, distributed key holders, withdrawal allowlisting with delays.
- Developer infrastructure is a primary attack vector in this sector, making build pipeline isolation and dependency integrity verification security-critical rather than engineering hygiene.
- AML and CTF controls function as security controls, preventing the platform from becoming a laundering conduit for the actors targeting it.

*Written by Glenn Ongalo | Nairobi, Kenya*
