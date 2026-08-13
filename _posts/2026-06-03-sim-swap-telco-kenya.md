---
title: "SIM Swap and the Telco Backdoor: How Kenya's Mobile Identity Is Being Exploited"
date: 2026-06-03 09:00:00 +0300
categories: [Cybersecurity, Kenya]
tags: [kenya, sim swap, safaricom, airtel, mpesa, telco, social engineering, mobile fraud, identity, soc]
description: SIM swap fraud investigations at Safaricom surged 327% in 2025. A single scheme involving 123,000 fraudulently registered SIM cards siphoned KSh 500 million through Fuliza. In Kenya, your phone number is your financial identity and it is under sustained attack.
image:
  path: https://images.unsplash.com/photo-1512941937669-90a1b58e7e9c?w=1200&h=500&fit=crop&q=80
  alt: Mobile phone as financial identity
---

## Your Phone Number Is Your Identity

In most countries, a phone number is a way to reach someone. In Kenya, it is a complete financial identity.

Your Safaricom number is linked to your M-PESA wallet, your bank account, your Fuliza overdraft, your KCB M-PESA loan, your KRA PIN, your email recovery, and your digital banking OTP delivery. In March 2026, Kenya's High Court explicitly recognised this reality, banning arbitrary phone number recycling by telecoms following a petition that argued a phone number had become a citizen's digital identity.

Courts have confirmed what attackers have known for years: control the SIM card and you control everything.

---

## The Scale of the Problem

SIM swap fraud investigations at Safaricom surged **327%** in 2025, rising to 47 cases, up from 11 the previous year. This is an increase in investigations, not necessarily in incidents, but it signals both growing attacker activity and growing awareness of the technique.

The more alarming number is elsewhere. A separately documented scheme involving **123,000 fraudulently registered SIM cards** siphoned **KSh 500 million** through Fuliza, Safaricom's overdraft service. This was not a sophisticated state-sponsored operation. It was organised fraud, scaled through the mobile registration system.

Safaricom handles roughly **28,000 SIM swap requests per day**. Even with robust controls, the volume creates opportunity. The company has reduced malicious swaps to approximately 40 out of every 750,000 transactions, a genuinely impressive ratio at scale. But at 28,000 daily requests, even a fraction of a percent of fraudulent swaps translates into real victims and real losses every single day.

---

## How SIM Swap Works in Practice

The attack has a consistent anatomy in the Kenyan context:

**Step 1: Intelligence gathering.** The attacker collects the victim's phone number, national ID number, and M-PESA transaction history. This information is available through social engineering, data purchased from dark web markets containing previously breached databases, or in some documented cases, through corrupt insiders at telcos or financial institutions.

**Step 2: Social engineering the telco.** The attacker contacts a Safaricom or Airtel shop, or in some cases the customer care line, impersonating the victim. Using the collected personal details to pass identity verification, they convince the agent that they need a replacement SIM because their original was lost or damaged.

**Step 3: The swap.** The victim's number is transferred to a SIM card the attacker controls. The victim's original card goes dark. All calls, SMS messages, and OTP codes now route to the attacker.

**Step 4: Account takeover.** With control of the phone number, the attacker resets banking passwords and M-PESA PIN using the "forgot password" flows that rely on SMS verification. Funds are transferred out, often within minutes, before the victim realises their service has gone offline.

The window between a successful SIM swap and the victim noticing something is wrong is typically 30 minutes to a few hours. In that window, everything linked to the number can be accessed and drained.

---

## The Airtel Interoperability Problem

In May 2026, Kenya Insights published an investigation into Airtel Kenya's Paybill 585555, documenting how Airtel's interoperability gateway connecting to M-PESA was allegedly being used as a destination for fraudulent fund transfers.

The investigation documented multiple cases where Safaricom M-PESA users reported unauthorised deductions routed to Paybill 585555, with no clear recourse or fraud resolution mechanism between the two carriers.

The underlying problem exposed by the investigation is structural. When a SIM-compromised user's funds are transferred through an interoperability gateway from Safaricom to Airtel, the fraud investigation must cross carrier boundaries. Neither carrier has a formal obligation to the other's customers. There is no inter-carrier fraud resolution framework. And there is no compensation mechanism.

A case documented in mid-2025 involving a Kenyan whose KSh 32,300 was incorrectly routed to a DRC account through Airtel's international transfer system took three weeks and a formal complaint to the COMESA competition body before the funds were returned. That resolution time, for a relatively small amount, illustrates the gap between the speed of mobile money and the speed of mobile money fraud response.

---

## The Insider Threat Dimension

SIM swap fraud in Kenya is not always an external attack. A significant portion involves insider access.

Investigations at Safaricom show that unauthorised access to internal systems and SIM swap facilitation by employees and agents is a documented pattern. The company's own reporting noted a decline in policy and procedure breaches involving unauthorised access, from 92 cases in 2024 to 57 in 2025, but the existence of insider-assisted fraud at that volume is significant for any organisation processing this scale of transactions.

The Mulot region of Bomet County has become synonymous with mobile money fraud syndicates in Kenya. Police raids on suspected swapper operations in the area have repeatedly uncovered SIM cards in bulk, exercise books containing personal information including M-PESA balances and Fuliza limits, and national identity card collections. The sophistication of the operation suggests intelligence coming from inside the ecosystem, not just social engineering from outside it.

---

## What Safaricom Is Doing

Safaricom has implemented several countermeasures that deserve acknowledgment:

**USIM protection.** Safaricom's self-whitelisting service allows customers to lock their number so it cannot be ported to another SIM without visiting a physical store with identification. This is a meaningful control that directly counters remote SIM swap attacks.

**SIM-Swap Check API.** Safaricom has made an API available to banks that allows them to query when a customer's SIM was last swapped before processing a high-value transaction. Six banks had signed up to this service as of 2023. If a SIM was swapped in the past 24 hours, the transaction can be flagged or held. This is the right architecture for the problem.

**SIM binding in My OneApp.** The April 2026 rollout of My OneApp introduced SIM binding, tying the application to the physical SIM card identifier on the device. This makes it significantly harder to take over an account remotely after a SIM swap, since the attacker would also need the victim's physical device.

The My OneApp rollout created significant friction for legitimate users, particularly dual-SIM users and the diaspora, illustrating the difficult tradeoffs between security and usability at scale. But the security architecture it introduced is sound.

---

## What Needs to Change Across the Ecosystem

Safaricom alone cannot solve this. SIM swap fraud is a systemic problem that requires responses at every layer:

**Real-time fraud intelligence sharing between Safaricom and Airtel.** A SIM swap at Safaricom should trigger a fraud flag at Airtel for any interoperability transactions on the same number within a defined window. There is currently no such mechanism.

**Mandatory SIM swap notification.** Any SIM swap should trigger an immediate notification to the email address and an alternative number registered on the account. The victim should know within seconds that their number has moved.

**Biometric verification for high-risk SIM swap requests.** The National Integrated Identity Management System (NIIMS) infrastructure exists. SIM swaps above a defined risk threshold, based on transaction history, balance, or linked account count, should require biometric verification that cannot be spoofed with a photocopied ID.

**Inter-carrier fraud resolution framework.** The CBK and Communications Authority need to mandate a formal fraud resolution agreement between Safaricom and Airtel. Cross-carrier fraud should have a defined escalation path, compensation timeline, and shared fraud database.

---

## Key Takeaways

- SIM swap fraud investigations at Safaricom rose 327% in 2025. A single documented scheme using 123,000 fraudulent SIM cards stole KSh 500 million through Fuliza.
- In Kenya, the phone number is the complete financial identity. SIM swap is not just account takeover. It is identity theft at the infrastructure level.
- Attacks follow a consistent pattern: intelligence gathering, social engineering the telco, swap, rapid account takeover within the victim's notification window.
- Insider-assisted fraud is a documented and significant component of the Kenyan SIM swap threat, not just external social engineering.
- The technical countermeasures exist: SIM-Swap Check APIs, USIM protection, SIM binding. The gap is adoption, enforcement, and cross-carrier coordination.

*Written by Glenn Ongalo | Nairobi, Kenya | June 2026*
