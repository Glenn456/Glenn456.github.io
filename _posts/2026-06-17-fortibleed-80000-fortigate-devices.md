---
title: "FortiBleed: 80,000 FortiGate Devices Compromised in a Single Campaign"
date: 2026-06-17 09:00:00 +0300
categories: [Cybersecurity, Threat Intelligence]
tags: [fortinet, fortigate, vpn, russia, campaign, firewall, threat intelligence, blue team, soc, cve]
description: A large-scale campaign codenamed FortiBleed has been systematically compromising Fortinet FortiGate firewalls and SSL VPN gateways since at least February 2026. Over 80,000 devices have been identified with working credentials tested by suspected Russian-speaking threat actors.
image:
  path: https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=1200&h=500&fit=crop&q=80
  alt: Enterprise firewall appliances in a rack
---

## What Is FortiBleed

Since at least February 2026, a large-scale automated campaign has been systematically targeting Fortinet FortiGate firewall and SSL VPN devices worldwide. Researchers at SOCRadar codenamed it **FortiBleed**.

The campaign has identified over 80,000 devices with working usernames and passwords, tested using automated tooling attributed to suspected Russian-speaking, financially motivated threat actors. The operation runs continuously, scanning the internet for exposed FortiGate management interfaces and VPN gateways, then testing extracted or leaked credentials at scale.

This is not a single intrusion. It is an industrialised credential harvesting and access operation running against one of the most widely deployed enterprise security products in the world.

---

## Why FortiGate Is a High-Value Target

FortiGate devices sit at the network perimeter. They are firewalls. They are VPN gateways. They are the devices that organisations trust to keep attackers out.

Compromising a FortiGate gives an attacker several immediate capabilities:

- Network-level visibility into all traffic passing through the device
- The ability to modify firewall rules, opening access to internal services
- VPN gateway access, which may enable direct tunnelling into the internal network
- Credentials and session data for other connected systems if the device is integrated with Active Directory or RADIUS

A compromised perimeter device is not just a foothold. It is a position of control over the entire network edge.

---

## How the Campaign Operates

The FortiBleed campaign follows a pattern consistent with other large-scale credential testing operations:

**Step 1: Discovery.** Automated scanners continuously identify internet-facing FortiGate devices by fingerprinting the login interface or management portal exposed on standard ports.

**Step 2: Credential sourcing.** The campaign uses credentials from multiple sources including previously disclosed FortiGate vulnerabilities that exposed configuration files containing hashed or plaintext credentials, dark web markets, and prior breach datasets. Several significant FortiGate vulnerabilities disclosed between 2022 and 2025 allowed unauthenticated attackers to read credential files from vulnerable devices.

**Step 3: Automated testing.** Scripts test extracted credentials against discovered devices at scale. The 80,000 figure represents devices where at least one credential pair produced a successful authentication.

**Step 4: Triage and access brokerage.** Confirmed access is either used directly or packaged and sold through initial access broker markets, where other threat actors purchase VPN or firewall access to specific organisations.

The campaign excludes machines located in Commonwealth of Independent States (CIS) countries, a consistent indicator of Russian-speaking threat actor origin that is used to avoid domestic law enforcement attention.

---

## What Organisations Need to Do Now

**Audit your exposed attack surface.** If your FortiGate management interface or SSL VPN portal is reachable from the public internet, that exposure needs to be evaluated. Management interfaces should never be internet-facing. VPN portals should use certificate-based authentication, not just credentials.

**Rotate all FortiGate credentials immediately.** If your device was running FortiOS during any of the vulnerability windows disclosed between 2022 and 2025, assume the credentials stored on that device have been collected. Rotate them regardless of whether you patched.

**Enable MFA on VPN access.** Credential-based VPN access is a single point of failure. FortiGate supports MFA through FortiToken and third-party RADIUS MFA providers. Enable it.

**Patch and stay patched.** Multiple FortiGate vulnerabilities have been actively exploited within days of disclosure. FortiGate devices should be on an aggressive patching schedule. If you cannot patch immediately, apply the mitigations Fortinet publishes alongside each advisory.

**Review VPN authentication logs.** Look for authentication attempts from unusual geolocations, IP ranges associated with VPN or proxy services, and unusual hours. Successful logins from IPs you do not recognise should be investigated immediately.

**Check for post-compromise indicators.** If you believe your device may have been tested or accessed, look for new administrator accounts, modified firewall policies, unexpected VPN tunnels, and scheduled tasks or scripts that were not created by your team.

---

## The Broader Pattern

FortiBleed is not unique. It fits a consistent pattern of threat actors running automated campaigns against enterprise security appliances, a category that has become one of the highest-value targets in the threat landscape.

The reasons are straightforward. Security appliances are perimeter devices with high privilege. They are often not covered by the same EDR and endpoint visibility that protects workstations and servers. They frequently run vendor-locked operating systems that are slower to patch. And their internet exposure is structural, not accidental.

In 2026, the attack surface that matters most is not the endpoint. It is the device that is supposed to protect the endpoint.

---

## Key Takeaways

- FortiBleed has identified over 80,000 FortiGate devices with working credentials, tested by suspected Russian-speaking threat actors running since February 2026.
- Compromising a FortiGate gives attackers control over the network perimeter, including firewall rules and VPN gateway access.
- The campaign sources credentials from prior FortiGate vulnerability disclosures, dark web markets, and breach datasets.
- Immediate actions: rotate all credentials, enable MFA on VPN, remove internet-facing management interfaces, and patch aggressively.
- Security appliances are now among the highest-value targets in the threat landscape precisely because of their privileged network position and historically weaker patching cycles.
