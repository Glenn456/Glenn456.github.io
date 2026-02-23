---
title: "Password Hashing & Salting: Why Storing Plaintext Passwords is Dangerous"
date: 2026-02-23 10:00:00 +0300
categories: [Cybersecurity, Application Security]
tags: [passwords, hashing, salting, cryptography, python, blue team, security engineering]
author: Ongalo Glenn
description: A deep dive into why plaintext password storage is catastrophic, how hashing works, why salting matters, and how to implement it correctly in Python.
---

## Introduction

In 2019, Facebook admitted to storing **hundreds of millions of user passwords in plaintext** — readable by any internal engineer with database access. In 2016, LinkedIn suffered a breach where **117 million passwords** were leaked, many cracked within days because they were hashed without salting using the weak MD5 algorithm.

These are not edge cases. Poor password storage is one of the most common and consequential security failures in software development — and understanding it is essential for any security professional.

In this post I'll break down exactly what goes wrong when passwords are stored incorrectly, how hashing and salting fix the problem, and how to implement it properly in Python. This is also one of the projects I built while developing my security engineering skills.

---

## The Problem: Plaintext Password Storage

Let's start with the worst case scenario.

When a user creates an account, their password gets saved to a database. If that password is stored exactly as typed — `mypassword123` — it is stored in **plaintext**.

Here's why that's catastrophic:

**Scenario:** An attacker exploits a SQL injection vulnerability and dumps your users table. They now have every username and its corresponding password in clear text. Every account is instantly compromised — not just on your platform, but on every other site where that user reused the same password.

A single breach becomes a cross-platform disaster.

---

## The First Solution: Hashing

A **hash function** takes an input of any length and produces a fixed-length output (the hash or digest). The critical properties are:

- **One-way** — you cannot reverse a hash back to the original input
- **Deterministic** — the same input always produces the same hash
- **Avalanche effect** — a tiny change in input produces a completely different hash

```python
import hashlib

password = "mypassword123"
hashed = hashlib.sha256(password.encode()).hexdigest()

print(hashed)
# Output: ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
```

Now instead of storing `mypassword123`, you store that hash. When the user logs in, you hash whatever they type and compare it to the stored hash — you never need to store or see the real password.

**If an attacker dumps your database now, they get hashes — not passwords.** A huge improvement. But it's still not enough.

---

## The Problem with Hashing Alone: Rainbow Tables

Here's the attack that breaks plain hashing.

Because hash functions are deterministic, attackers can **pre-compute** hashes for millions of common passwords and store them in a lookup table called a **rainbow table**.

| Password | SHA-256 Hash |
|---|---|
| password | 5e884898da... |
| 123456 | 8d969eef6e... |
| mypassword123 | ef92b778ba... |
| letmein | 1c8bfe8f80... |

An attacker dumps your database, looks up each hash in their rainbow table, and instantly recovers any password that appears in it. No computation needed — it's just a lookup.

**Common passwords are cracked in milliseconds.**

---

## The Real Solution: Salting

A **salt** is a random string of characters generated uniquely for each user and added to their password before hashing.

```python
import hashlib
import os

password = "mypassword123"

# Generate a unique random salt for this user
salt = os.urandom(32)  # 32 bytes of randomness

# Combine salt + password, then hash
salted_password = salt + password.encode()
hashed = hashlib.sha256(salted_password).hexdigest()

print(f"Salt: {salt.hex()}")
print(f"Hash: {hashed}")
```

The salt is stored alongside the hash in the database (it doesn't need to be secret — its purpose is uniqueness, not secrecy).

**Why this defeats rainbow tables:**

Even if two users have the identical password `mypassword123`, their salts will be different, producing completely different hashes:

| User | Password | Salt | Hash |
|---|---|---|---|
| alice | mypassword123 | `a3f9...` | `7d2c...` |
| bob | mypassword123 | `b71e...` | `9a4f...` |

An attacker would need to compute a separate rainbow table for every unique salt — which is computationally infeasible at scale.

---

## The Right Way: Using bcrypt

While the examples above illustrate the concepts, in production you should **never implement your own hashing scheme**. Instead, use a purpose-built password hashing algorithm like **bcrypt**, **Argon2**, or **scrypt**.

These algorithms are specifically designed to be:
- **Slow by design** — making brute-force attacks expensive
- **Adaptive** — you can increase the work factor as hardware gets faster
- **Salt-handling built in** — bcrypt generates and stores the salt automatically

```python
import bcrypt

# --- STORING A PASSWORD ---
password = "mypassword123".encode()

# bcrypt automatically generates a salt and hashes
hashed = bcrypt.hashpw(password, bcrypt.gensalt())

print(hashed)
# Output: b'$2b$12$EXAMPLEhashEXAMPLEhashEXAMPLEhashEXAMPLEhashEXAMPL'

# --- VERIFYING A PASSWORD AT LOGIN ---
login_attempt = "mypassword123".encode()

if bcrypt.checkpw(login_attempt, hashed):
    print("Login successful")
else:
    print("Invalid password")
```

The `$2b$12$` prefix in the output tells you the algorithm version and **work factor** (12 rounds). A higher work factor means more computation per hash — making brute force slower.

---

## Comparing the Algorithms

| Algorithm | Designed For | Salting | Recommended? |
|---|---|---|---|
| MD5 | General hashing | ❌ Manual | ❌ Never for passwords |
| SHA-1 | General hashing | ❌ Manual | ❌ Never for passwords |
| SHA-256 | General hashing | ❌ Manual | ❌ Not ideal for passwords |
| bcrypt | Passwords | ✅ Built-in | ✅ Yes |
| Argon2 | Passwords | ✅ Built-in | ✅ Yes (modern standard) |
| scrypt | Passwords | ✅ Built-in | ✅ Yes |

MD5 and SHA-256 are fast — great for checksums and data integrity, terrible for passwords because speed helps attackers.

---

## Real-World Breach Lessons

**RockYou (2009)** — 32 million passwords stored in plaintext. This breach produced the infamous `rockyou.txt` wordlist that is still used in penetration testing today.

**LinkedIn (2016)** — 117 million passwords hashed with unsalted SHA-1. Cracked en masse within days of the breach being published.

**Adobe (2013)** — 153 million passwords encrypted (not hashed) with 3DES using the same key. Because encryption is reversible, once the key was found, all passwords were exposed.

**The pattern is clear:** organisations that cut corners on password storage pay the price when breaches happen — and breaches always happen eventually.

---

## What This Means for SOC Analysts

As a SOC analyst, understanding password storage matters in several ways:

- **Incident response** — when investigating a data breach, you need to assess the blast radius. Were passwords stored in plaintext? Hashed? Salted? This determines the urgency of forcing password resets.
- **Vulnerability assessment** — identifying applications in your environment that use weak hashing algorithms (MD5, SHA-1) is a real finding with real risk.
- **Threat intelligence** — when credential dumps appear on dark web forums, salted bcrypt hashes are far less dangerous than unsalted MD5 hashes. Knowing the difference informs how quickly you need to respond.

---

## Final Thoughts

Password hashing and salting is one of those fundamentals that seems simple on the surface but has real depth — and real consequences when done wrong. Building this project in Python helped me understand not just *what* to do, but *why* each component matters.

The rule of thumb is straightforward: always use a purpose-built password hashing library like bcrypt or Argon2, never roll your own, and never store plaintext passwords. The breaches that fill security headlines are proof that these lessons still aren't universally applied.

---

*Check out the full project code on my [GitHub](https://github.com/glenn456). For questions or discussion, connect with me on [LinkedIn](https://www.linkedin.com/in/ongalo-glenn).*
