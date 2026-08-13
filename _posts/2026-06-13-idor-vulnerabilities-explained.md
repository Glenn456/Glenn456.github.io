---
title: "IDOR: The Access Control Flaw That Keeps Costing Millions"
date: 2026-06-13 09:00:00 +0300
categories: [Cybersecurity, Threat Intelligence]
tags: [idor, owasp, web security, access control, blue team, soc, api security, broken access control]
description: Insecure Direct Object Reference is consistently one of the most exploited web vulnerabilities. It requires no special tools, no exploit code, and no technical sophistication. Just change a number in a URL. Here is how it works and how to find and fix it.
image:
  path: https://images.unsplash.com/photo-1555066931-4365d14bab8c?w=1200&h=500&fit=crop&q=80
  alt: Web application code and authorisation logic
---

## What IDOR Is

Insecure Direct Object Reference (IDOR) is a broken access control vulnerability that occurs when an application exposes internal object identifiers and fails to verify whether the requesting user is actually authorised to access the referenced object.

It is OWASP's number one web application security risk category: Broken Access Control.

The simplest version looks like this. A user logs in and views their invoice at:

```
https://app.example.com/invoice?id=1042
```

They change `1042` to `1041` and see someone else's invoice. No authentication bypass. No exploit code. Just a number change.

The application verified that the user was logged in. It never verified whether this specific user was allowed to see invoice 1041.

---

## Why IDOR Is So Common

IDOR is common because it is easy to introduce and invisible during normal testing.

Developers build features under time pressure. They implement authentication correctly, verifying that users are logged in before serving protected resources. But they frequently skip or incompletely implement authorisation, the second check that asks whether this specific user is allowed to access this specific resource.

The difference:
- **Authentication:** Are you who you say you are?
- **Authorisation:** Are you allowed to do what you are trying to do?

Failing authentication is visible. You get a 401 or a redirect to a login page. Failing authorisation is silent. You get a 200 and someone else's data.

---

## IDOR Patterns to Know

**Sequential integer IDs**

The most common pattern. Object IDs are auto-incremented integers assigned by a database. Predictable, easy to enumerate.

```
/api/users/1001
/api/users/1002
/api/users/1003
```

**GUIDs that are not actually validated**

Some developers believe using a UUID instead of a sequential ID prevents IDOR. It does not. If the application does not validate that the requesting user owns the referenced UUID, the attack still works. UUIDs prevent guessing but do not prevent disclosure once an attacker obtains a valid identifier through another path.

**File download references**

```
/download?file=report_2024_user1042.pdf
```

Changing the filename or user ID in a download URL is a classic IDOR vector, and one of the most impactful because the objects being referenced are often sensitive documents.

**Indirect references in API responses**

An API response for a user's profile might include an `account_id` field that can then be used in a separate request to access account details. If that second endpoint does not re-verify ownership, the `account_id` is an IDOR vector even if the user never typed it manually.

---

## Real-World Impact

IDOR vulnerabilities have been at the root of some of the most significant data exposures in recent years. Any breach where an attacker accessed records belonging to other users by manipulating identifiers in requests is an IDOR incident.

The pattern appeared in the HackTheBox Cap machine, where a web dashboard allowed any authenticated user to download any network capture file by changing a single digit in the URL. The IDOR alone gave read access to another user's capture. That capture happened to contain plaintext FTP credentials, which then enabled SSH access to the server. One access control failure cascaded into a full system compromise.

---

## How to Find IDOR

**Manual testing**

Create two test accounts. Log in as Account A and perform every action that returns or references an object with an ID. Then, while authenticated as Account B, attempt to access every ID that belongs to Account A. Any successful cross-account access is an IDOR.

**Parameter discovery**

Capture all requests through a proxy like Burp Suite. Look for numeric or alphanumeric identifiers in query parameters, POST body fields, headers, and API endpoints. Every identifier is a potential IDOR target.

**Fuzzing**

Automate the ID manipulation. Tools like Burp Suite's Intruder or custom scripts can iterate through ID ranges and flag any response that returns data it should not.

**Check indirect references**

Look for IDs embedded in API responses that are not directly visible in the UI. These are often overlooked because they do not appear in browser URLs.

---

## How to Fix It

**Server-side ownership verification on every request**

For every request that accesses an object, verify at the server that the authenticated user owns or has permission to access that specific object. Not just that they are logged in. Not just that the object exists. That this user is allowed to see it.

```python
# Wrong: only checks authentication
def get_invoice(invoice_id):
    return Invoice.query.get(invoice_id)

# Right: verifies ownership
def get_invoice(invoice_id):
    invoice = Invoice.query.get(invoice_id)
    if invoice.user_id != current_user.id:
        abort(403)
    return invoice
```

**Indirect reference maps**

Instead of exposing database IDs directly, map them to session-specific tokens. The user sees `token_a3f9` in the URL. The server maps that token to object ID 1042 for this specific session. Even if an attacker guesses a token, it only resolves to their own objects.

**Centralise access control checks**

Access control logic scattered across individual endpoints is easy to miss. Centralise it in a middleware layer or permission service that every request passes through.

**Add authorisation to your testing checklist**

Authentication testing is standard. Authorisation testing often is not. Explicitly test that users cannot access each other's resources as part of every feature's security review.

---

## Key Takeaways

- IDOR is the most exploited web vulnerability category in 2026. It requires no technical tools, just changing an identifier in a request.
- It is an authorisation failure, not an authentication failure. The application knows who you are. It just does not check what you are allowed to see.
- Common patterns include sequential integer IDs, GUIDs without ownership validation, file download references, and indirect IDs embedded in API responses.
- The fix is simple in principle and frequently missed in practice: verify ownership on every request that accesses a user-specific object.
- IDOR vulnerabilities compound. Read access to the wrong file can cascade into credential exposure, account takeover, or full system compromise depending on what that file contains.
