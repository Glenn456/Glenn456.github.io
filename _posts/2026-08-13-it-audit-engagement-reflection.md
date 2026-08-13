---
title: "Seven Weeks Inside an IT Audit: Notes From a Cyber Risk Engagement"
date: 2026-08-13 14:00:00 +0300
categories: [Cybersecurity, Professional]
tags: [it audit, governance, risk, compliance, controls testing, cyber risk, assurance, kenya]
description: I spent the past seven weeks working on an IT audit engagement for a cyber risk management company. Here is what the work actually involved and what it changed about how I think about security.
image:
  path: https://images.unsplash.com/photo-1454165804606-c3d57bc86b40?w=1200&h=500&fit=crop&q=80
  alt: Audit documentation and controls review
---

## The Engagement

For the past seven weeks I have been working on an IT audit engagement with a cyber risk management company, assessing the control environment of client organisations across their technology estate.

I wanted to write this up while it is still fresh, partly to consolidate what I learned and partly because audit work is poorly understood by people who come to security from a technical direction, which was my own path.

The short version: it changed how I think about security controls more than any technical training I have done.

---

## What an IT Audit Actually Involves

Before this engagement, my mental model of audit was compliance theatre. A checklist, some screenshots, a report nobody reads.

That model was wrong, and the reason it was wrong is instructive.

An IT audit asks a specific question about every control: **does this control operate effectively, and how do you know?**

Not whether the control exists. Not whether there is a policy describing it. Whether it works, consistently, and whether there is evidence proving it works.

That question is much harder to answer than it sounds, and answering it honestly exposes gaps that technical assessments routinely miss.

---

## The Phases

**Planning and scoping.** Understanding the business, the systems that support it, and where the material risks sit. You cannot audit everything, so the work begins with deciding what matters. This meant reviewing the organisational structure, the technology estate, prior audit findings, and the risk register, then agreeing scope with stakeholders.

**Control identification.** Documenting the controls the organisation believes it operates, across access management, change management, backup and recovery, incident response, network security, and third-party management.

**Design effectiveness testing.** Would this control, as designed, actually mitigate the risk it is intended to address? A surprising number of controls fail here before you even test whether they operate. A quarterly access review that has no defined reviewer, no defined criteria, and no remediation path is not a control. It is an intention.

**Operating effectiveness testing.** This is where the real work happens. Selecting samples, requesting evidence, and testing whether the control operated as designed throughout the period. Not on the day you asked. Throughout the period.

**Findings and reporting.** Documenting exceptions, assessing their risk, agreeing management responses, and writing it up so that someone who was not in the room understands what was found and why it matters.

---

## What Surprised Me

**Evidence is everything, and most organisations do not generate it.**

The most common finding was not a missing control. It was a control that probably operates but cannot be evidenced. Access reviews conducted in conversation with no record. Change approvals given verbally. Backup restoration tested at some point but not documented.

From an audit perspective, an unevidenced control is an untested control. That felt harsh to me initially. It stopped feeling harsh the first time an organisation could not tell me whether a departed employee's access had been revoked, because nobody had recorded doing it.

**Sampling reveals things that scanning does not.**

Automated tools tell you the current state. Sampling across a period tells you whether the control held over time. Pulling twenty user access provisioning records across six months surfaces the ones that skipped approval, the ones granted before the start date, and the ones where the approver was the requester. No vulnerability scanner finds that.

**The gap between policy and practice is where risk lives.**

Nearly every organisation has adequate policies. The interesting question is what happens on a Friday afternoon when a production issue needs an emergency change and the approver is unreachable. The documented process describes the ideal path. The audit tests the actual path.

**Interviews produce better findings than documentation review.**

Reading a procedure tells you what should happen. Asking the person who performs it to walk you through what they actually did last Tuesday tells you what does happen. The difference between those two is usually the finding.

---

## What Changed About How I Think

I came into this engagement thinking about security as a technical problem: find the vulnerability, close it, move on.

Audit reframes it as a **sustainability** problem. Not "is this system secure right now" but "is there a repeatable, evidenced process that keeps it secure as people change roles, systems get patched, and vendors get onboarded."

That reframing has practical consequences for how I approach engineering work now:

**Design controls to produce evidence automatically.** If a control requires someone to remember to document it, it will fail. Access recertification that generates a signed record. Change approval that lives in a ticketing system. Backup verification that logs its results. Build the evidence into the mechanism.

**Assume every control will be tested by someone who was not there.** Would a reasonable person, six months from now, be able to determine that this operated correctly? If not, the control has a gap regardless of whether it works today.

**Separate the control from the person.** Controls that depend on a specific individual's diligence are single points of failure. When that person is on leave, the control is not operating.

**Findings need a risk rating that reflects business impact, not technical severity.** A missing patch on an isolated internal test server and a missing patch on an internet-facing payment gateway are not the same finding, even if the CVSS score is identical. Learning to articulate that difference clearly was one of the more valuable parts of the engagement.

---

## Where Audit and Security Operations Meet

The most useful realisation was how directly audit findings translate into detection engineering.

Every control weakness identified in an audit is a place where an attacker could operate undetected. A gap in privileged access review is a gap in detecting privilege escalation. A gap in change management is a gap in detecting unauthorised system modification. A gap in third-party access governance is exactly the gap that produced the KSh 517 million contractor breach reported in the Kenyan banking sector.

An audit report, read by a detection engineer, is a prioritised list of where to build monitoring.

That connection is not made often enough. Audit and security operations frequently sit in different functions, report to different leaders, and rarely share findings. The organisations that connect them get significantly more value from both.

---

## Closing Thought

If you are a technical security practitioner who has dismissed audit as bureaucracy, I would encourage reconsidering. The discipline of proving that a control operates, consistently, with evidence, is a different skill from finding vulnerabilities, and it is one that makes you materially better at building security that lasts.

The vulnerability you find today gets patched. The control that operates reliably prevents the next hundred.

*Written by Glenn Ongalo | Nairobi, Kenya*
