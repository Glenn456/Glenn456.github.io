---
title: "How One Poisoned npm Package Breached Grafana, GitHub and OpenAI in the Same Week"
date: 2026-05-21 09:00:00 +0300
categories: [Cybersecurity, Incident Response]
tags: [supply chain, npm, github, grafana, threat intelligence, blue team, soc, incident response]
description: The Mini Shai-Hulud campaign turned a trusted open-source package into a weapon that hit Grafana Labs, GitHub, OpenAI and Mistral AI in a single coordinated wave. Here is exactly what happened and what defenders need to take away.
image:
  path: https://images.unsplash.com/photo-1618401471353-b98afee0b2eb?w=1200&h=500&fit=crop&q=80
  alt: Developer workstation and build pipeline
---

## What Just Happened

On May 11, 2026, at 19:20 UTC, an attacker published 84 malicious versions across 42 npm packages belonging to TanStack, a widely used open-source JavaScript framework. The attack was detected within 26 minutes by an external researcher. But 26 minutes was long enough.

By the time the malicious packages were pulled, they had already been consumed by CI/CD pipelines at some of the most recognised names in the technology industry. Grafana Labs, GitHub itself, OpenAI, and Mistral AI were all confirmed victims of what researchers are calling the Mini Shai-Hulud campaign, attributed to a threat group tracked as TeamPCP.

This is one of the most significant software supply chain attacks of 2026, and it illustrates a systemic vulnerability in how modern development pipelines consume and trust open-source dependencies.

---

## How the Attack Was Constructed

The TanStack attack was technically sophisticated, combining three distinct techniques to achieve what researchers describe as a "Pwn Request" pattern.

![Server infrastructure representing CI/CD pipelines](https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=1200&q=80)

**Step 1: GitHub Actions Cache Poisoning**

TanStack uses GitHub Actions for its CI/CD pipeline. The attacker exploited a misconfiguration in how `pull_request_target` workflows handle fork contributions. By poisoning the GitHub Actions cache across the fork and base repository trust boundary, the attacker was able to influence the build environment without needing direct write access to the repository.

**Step 2: OIDC Token Extraction**

During the build process, the attacker's malicious code extracted an OpenID Connect (OIDC) token from the GitHub Actions runner process at runtime. OIDC tokens are used to authenticate workloads to cloud services and other systems, including npm itself.

**Step 3: Malicious Package Publication**

Using the extracted OIDC token, the attacker published 84 malicious versions across 42 `@tanstack/*` packages to the npm registry. These packages contained credential-stealing code that executed silently in any environment that installed them.

The entire operation from first malicious publish to detection took under 30 minutes.

---

## The Grafana Breach: A Masterclass in Incident Response

Grafana Labs was one of the highest-profile victims. Their CI/CD workflow consumed the malicious TanStack packages on May 11, which executed the credential-stealing payload inside their GitHub Actions environment and exfiltrated GitHub workflow tokens to the attacker.

Grafana's security team detected the malicious activity and immediately rotated a large number of GitHub workflow tokens. But one token was missed.

That single missed token was enough.

The attacker used it to gain access to Grafana's private GitHub repositories, downloading the company's codebase including internal operational documents. On May 16, they issued a ransom demand threatening to release the stolen code publicly.

Grafana refused to pay, citing FBI guidance that payment only encourages future attacks and provides no guarantee of deletion. The extortion group CoinbaseCartel had already listed Grafana on its dark web site by May 15.

Grafana's customers include Nvidia, Microsoft, and Anthropic. No customer production systems were confirmed compromised.

---

## GitHub Was Hit Too

In a related development, GitHub itself confirmed that its internal repositories were accessed by TeamPCP. GitHub CISO Alexis Wales identified the initial access vector: a malicious version of the Nx Console VS Code extension, which had 2.2 million installs on the VS Code Marketplace.

A GitHub employee installed the compromised extension, which stole developer credentials. Those credentials were then used to move laterally through GitHub's CI/CD pipelines, ultimately exfiltrating approximately 3,800 private code repositories.

---

## What SOC Analysts and Development Teams Need to Do Right Now

**Audit your npm dependencies.** If your organisation uses any `@tanstack/*` packages, verify which versions are installed. Any build that ran on May 11 during the 26-minute window may have consumed the malicious versions.

**Review GitHub Actions workflows using `pull_request_target`.** This trigger is inherently risky when combined with access to secrets. Confirm no workflow passes repository secrets to untrusted code from forks.

**Enforce token expiry and minimal scope.** The Grafana breach was extended by a single missed token during rotation. Short expiry windows and post-incident token audits are process controls that would have contained this faster.

**Monitor CI/CD network behaviour.** Your build pipeline should have predictable outbound connections. Unexpected DNS lookups or connections from a GitHub Actions runner to unusual endpoints during a build should trigger an immediate alert.

**Implement Software Composition Analysis.** SCA tooling that alerts when a dependency releases an unusual number of versions in a short window would have flagged 84 versions in six minutes as an anomaly immediately.

---

## Key Takeaways

- TeamPCP compromised TanStack npm packages using GitHub Actions cache poisoning and OIDC token extraction, hitting Grafana, GitHub, OpenAI and Mistral AI in the same campaign.
- The entire attack window was under 30 minutes. Pipeline hygiene matters more than detection speed here.
- One missed token during Grafana's incident response extended the breach from containment to full codebase exfiltration.
- `pull_request_target` workflows with access to secrets are a systemic risk across GitHub's ecosystem.
- The attack required no zero-days. It exploited legitimate tools and trusted relationships.

The most dangerous packages in your dependency tree are the ones you trust the most.
