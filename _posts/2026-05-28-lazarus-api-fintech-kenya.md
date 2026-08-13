---
title: "State-Sponsored Hackers Are Targeting Kenyan Fintechs. Here Is How."
date: 2026-05-28 09:00:00 +0300
categories: [Cybersecurity, Kenya]
tags: [kenya, lazarus, north korea, fintech, api, supply chain, threat intelligence, aml, banking, soc, east africa]
description: North Korea's Lazarus Group has been running coordinated campaigns against cryptocurrency and fintech organisations in Kenya. Combined with organised criminal exploitation of the API layer linking banks to mobile money, Kenya's fintech stack faces threats from both state and non-state actors simultaneously.
image:
  path: https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=1200&h=500&fit=crop&q=80
  alt: Cascading code representing advanced persistent threat activity
---

## Two Threat Actors, One Attack Surface

Kenya's financial technology sector faces an unusual threat environment. Most markets deal with either state-sponsored attacks or organised criminal activity. Kenya is dealing with both, simultaneously, targeting the same infrastructure.

On one side: North Korea's Lazarus Group and affiliated DPRK-linked actors running coordinated campaigns against cryptocurrency and fintech organisations, with Kenya explicitly identified as a target country. On the other: organised criminal networks exploiting the API and middleware layer that connects Kenya's banks, fintechs, mobile network operators, and payment rails.

The attack surface they are both targeting is the same one: the connective tissue of Kenya's digital economy.

---

## Lazarus Group in East Africa

Darktrace's 2026 State of Cybersecurity in the Finance Sector report identified coordinated campaigns by state-sponsored actors linked to North Korea's Lazarus Group targeting cryptocurrency and fintech organisations across multiple countries, with Kenya listed alongside the United Kingdom, Spain, Nigeria, and Qatar as confirmed targets.

The campaign used three distinct techniques:

**Malicious npm packages.** Attackers published packages to the npm registry under names mimicking legitimate developer tools. Kenyan fintech developers searching for common packages and installing typosquatted or name-confused alternatives unknowingly executed malicious code that established persistent access.

**BeaverTail and InvisibleFerret malware.** These are previously undocumented malware strains identified in this campaign. BeaverTail is an infostealer that targets browser-stored credentials and cryptocurrency wallet data. InvisibleFerret is a backdoor that establishes persistent remote access. Both were delivered through the compromised npm packages and through social engineering targeting developers.

**React2Shell exploitation (CVE-2025-55182).** This vulnerability in the React2Shell framework allowed attackers to escalate from initial access to persistent backdoor installation on development and staging servers.

The objective in the Kenyan context was primarily financial. DPRK-linked groups are assessed by multiple intelligence agencies to use cryptocurrency theft and financial fraud to fund state programmes, making fintech platforms direct targets for what amounts to state-sponsored financial crime.

---

## The API Layer Attack

A different category of threat, organised criminal exploitation of the middleware and API infrastructure connecting Kenya's financial institutions, is arguably more immediately damaging at scale.

The most documented case in the region is the 2020 breach at Uganda's Pegasus Technologies, which illustrates the vulnerability pattern that remains unresolved across East Africa.

Attackers exploited middleware that linked Ugandan banks to mobile money wallets through an API layer. Using approximately 2,000 fraudulently registered SIM cards and automated tooling, they repeatedly triggered small mobile money transactions through the middleware, exploiting timing vulnerabilities and weak transaction validation to siphon approximately USD 3 million before the pattern was detected.

The attack did not breach the bank's core systems. It did not require exploiting a zero-day vulnerability. It exploited the weakest point in a connected ecosystem: the API layer that handles interoperability, with insufficient rate limiting, anomaly detection, and transaction validation controls.

This vulnerability architecture is not unique to Uganda. Kenya's banks, fintechs, mobile operators, and SACCOs are connected through a similar middleware and API ecosystem. The CBK's National Payments Strategy 2022-2025 explicitly committed to developing API standards, but the gap between policy commitment and implementation means the attack surface documented in Uganda continues to exist in Kenya.

---

## Why Fintech Is a High-Value Target for State Actors

North Korea's cyber programme has a specific economic logic. The country is under comprehensive international sanctions that restrict its access to the global financial system. State-sponsored hacking, particularly targeting cryptocurrency platforms and fintech companies, is a documented mechanism for sanctions evasion and revenue generation.

The UN Panel of Experts has estimated that DPRK-linked actors have stolen more than USD 3 billion from cryptocurrency and fintech organisations between 2017 and 2024. The targeting has become more sophisticated over time, moving from direct exchange hacks to supply chain attacks targeting the developer tools and npm packages that fintech companies use to build their products.

Kenya is a high-value target in this context for specific reasons:

**Cryptocurrency adoption.** Kenya is among Africa's top four cryptocurrency adoption markets, alongside South Africa, Nigeria, and Egypt. The Virtual Asset Service Providers Act (VASPA) that came into force in November 2025 established a formal licensing framework for crypto, creating a defined set of regulated, accessible targets.

**Digital lending infrastructure.** The CBK licensed approximately 110 new digital credit providers in 2025, bringing the total to 195 licensed entities. Many of these are relatively young organisations building on shared APIs and third-party infrastructure, with less mature security programmes than established banks.

**Developer ecosystem.** Nairobi has a large and active technology developer community building on open-source tools and public package registries. Supply chain attacks targeting npm packages are designed to cast a wide net across exactly this kind of ecosystem.

---

## The AML/CTF Dimension

Kenya's grey-listing by the Financial Action Task Force (FATF) in 2024, while since resolved, exposed a systemic gap between Kenya's formal AML/CTF regulatory framework and its practical implementation across the financial sector.

The grey-listing was corrective rather than preventive. Kenya was added to the list because enforcement was lagging behind the framework on paper. The response, including strengthened CBK guidelines on AML/CTF for digital financial services, the passage of VASPA with mandatory AML controls for virtual asset providers, and increased scrutiny of cross-border cryptocurrency flows, was driven by international pressure.

For the financial sector, the AML/CTF gap matters in the context of state-sponsored financial crime specifically. DPRK-linked actors move stolen cryptocurrency through mixer services and a series of conversions designed to make the funds appear as legitimate trading profits before they reach fiat currency. If Kenyan fintechs and virtual asset providers have weak transaction monitoring and suspicious activity reporting, they become attractive conversion points for funds that originated in North Korean cyberattacks anywhere in the world.

The cyber risk and the AML risk are not separate problems. They are two views of the same underlying vulnerability.

---

## What Kenyan Fintechs Need to Do

**Audit your software dependencies.** Every Kenyan fintech organisation using npm packages or open-source libraries should run software composition analysis on their codebase immediately. The Lazarus Group's campaign targets developer infrastructure. If your developers are pulling packages from public registries without integrity verification, you have exposure.

**Implement API security monitoring.** Transaction velocity anomalies, unusual API call patterns, and out-of-hours automated access to payment APIs should all generate alerts. The Uganda Pegasus breach pattern, high-frequency small transactions through a middleware layer, would have been detectable with basic API behavioural monitoring.

**Build threat intelligence sharing into your sector posture.** Lazarus Group campaigns leave specific indicators of compromise. DPRK malware families have documented signatures. KE-CIRT/CC publishes threat intelligence that is not being consumed fast enough by the organisations it is meant to protect.

**Treat third-party access as a primary attack surface.** Every API integration, every vendor with system access, and every middleware provider in your payment stack is a potential entry point. Map them, audit them, and apply least-privilege principles to every integration.

**Strengthen your cryptocurrency transaction monitoring.** If your platform handles virtual assets, your transaction monitoring system needs to screen for known DPRK-linked wallet addresses and mixing service patterns. This is both a cyber defence measure and an AML control.

---

## Key Takeaways

- Lazarus Group and DPRK-affiliated actors are running confirmed campaigns against Kenyan fintech and cryptocurrency organisations using npm supply chain attacks, novel malware strains, and developer social engineering.
- The API and middleware layer connecting Kenya's banks, mobile operators, and fintechs is a structurally under-secured attack surface that organised criminal actors have already successfully exploited in the region.
- Kenya's FATF grey-listing exposed an execution gap in AML/CTF controls that creates secondary exposure to cryptocurrency flows from state-sponsored theft.
- The 195 licensed digital credit providers and rapidly growing crypto sector create a large, accessible target set for financially motivated state actors.
- Cyber defence and AML compliance are not separate functions in the Kenyan fintech context. They are addressing the same threat through different lenses.

*Written by Glenn Ongalo | Nairobi, Kenya | May 2026*
