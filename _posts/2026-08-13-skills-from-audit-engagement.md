---
title: "Eight Skills I Picked Up on an IT Audit Engagement"
date: 2026-08-13 16:00:00 +0300
categories: [Cybersecurity, Professional]
tags: [skills, it audit, governance, risk, compliance, professional development, soc, career]
description: A practical breakdown of the specific capabilities I developed over seven weeks of IT audit work, and how each one transfers to security operations and detection engineering.
image:
  path: https://images.unsplash.com/photo-1434030216411-0b793f4b4173?w=1200&h=500&fit=crop&q=80
  alt: Professional skills development and study
---

## Why Write This Down

Skills learned on an engagement fade quickly unless you articulate them. This is my attempt to name what actually developed over seven weeks of IT audit work for a cyber risk management company, and to be specific about how each capability transfers.

---

## 1. Control Design Assessment

**What it is:** Evaluating whether a control, as designed, would actually mitigate the risk it targets, before testing whether it operates.

This is a distinct analytical skill. A control has to have a defined owner, a defined trigger or frequency, defined criteria for what constitutes a pass, and a defined remediation path when it fails. Missing any of those and the control cannot work reliably regardless of good intentions.

**Where it transfers:** Directly into building security processes that survive contact with reality. I now design controls by asking what happens when the owner is on leave, and what happens when the check fails.

---

## 2. Evidence-Based Testing and Sampling

**What it is:** Selecting a representative sample across a period and testing whether the control operated consistently, rather than checking current state.

The methodology matters. Sample size relative to population and control frequency. Random versus judgemental selection. Documenting the selection basis so the test is reproducible.

**Where it transfers:** Verification work of any kind. When someone tells me a process is followed, my instinct now is to ask for twenty instances across six months rather than one example from today.

---

## 3. Risk Articulation and Rating

**What it is:** Translating a technical finding into business impact terms, and defending the rating.

A finding rated High needs to survive a conversation with a manager who disagrees. That requires articulating the specific scenario, the likelihood, the consequence, and the existing compensating controls. Technical severity alone is not a rating.

**Where it transfers:** Everything. Alert triage severity, vulnerability prioritisation, incident classification, and any conversation where security needs a decision from someone outside security.

---

## 4. Structured Interviewing

**What it is:** Getting accurate information from process owners without leading them, and identifying the gap between the documented process and the actual one.

The technique that worked best: ask people to walk through the most recent real instance rather than describing the process in general terms. General descriptions produce the ideal path. Specific instances produce what happened.

**Where it transfers:** Incident response interviews, threat modelling sessions, and any requirements gathering. The skill of getting people to describe reality rather than intention is broadly useful.

---

## 5. Working Paper Discipline

**What it is:** Documenting testing in a way that lets someone else reach the same conclusion from the same evidence, months later, without asking you a question.

What was tested, why that sample, what evidence was obtained, what the result was, and what conclusion follows. Sounds mechanical. Turned out to be the discipline that most improved my technical work.

**Where it transfers:** Incident documentation, detection rule development, and lab writeups. My HTB and DFIR writeups improved noticeably during this period because the underlying discipline is identical.

---

## 6. Access Management Testing

**What it is:** Testing the full identity lifecycle rather than a point-in-time permissions list. Provisioning with approval evidence, modification on role change, recertification with reviewer accountability, and deprovisioning with timing.

The consistent finding pattern is at the ends: joiners granted access before approval, and leavers retaining access after departure.

**Where it transfers:** Directly into detection engineering. Every gap in access lifecycle governance is a place where a detection rule adds value. Orphaned accounts, access granted outside the approval workflow, and permissions that exceed role baseline are all detectable if you know to look.

---

## 7. Change Management Assessment

**What it is:** Testing whether changes to production systems follow an approved, documented, reversible process, including emergency changes.

Emergency change is where the interesting findings are. Every organisation has an expedited path. Very few retrospectively review whether emergency changes were genuinely urgent or whether the path is being used to bypass approval.

**Where it transfers:** Unauthorised change detection. If you know what the approved change process produces as evidence, you can detect changes that lack it. Configuration drift monitoring correlated against the change record is a strong detection use case that I now understand how to build.

---

## 8. Report Writing for a Non-Technical Audience

**What it is:** Writing findings that a board member understands and can act on, without either overstating the risk or burying it in technical detail.

The structure that works: what was found, why it matters in business terms, what could happen, what should be done, and by when. Precision without jargon. The hardest part is being clear about severity without inflating it, because credibility is spent quickly.

**Where it transfers:** Incident reports, security metrics, and any communication upward. This is the skill that determines whether security recommendations get funded.

---

## The Meta Skill

The capability underneath all eight is **thinking in terms of assurance rather than assessment**.

An assessment asks: is this secure right now. Assurance asks: what evidence would convince a reasonable, sceptical person that this remains secure over time, and does that evidence exist.

That question is more demanding and more useful. It is also the question that separates security work that holds from security work that decays the moment attention moves elsewhere.

---

## Key Takeaways

- Control design assessment, evidence-based sampling, and risk articulation are the three core audit skills with the widest transfer into security operations.
- Working paper discipline improves technical documentation of every kind, including detection engineering and incident response.
- Access lifecycle and change management testing map directly onto high-value detection use cases.
- Report writing for non-technical audiences determines whether security findings result in action.
- The underlying shift is from assessment to assurance: proving a control holds over time rather than confirming it works today.

*Written by Glenn Ongalo | Nairobi, Kenya*
