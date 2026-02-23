---
title: "Security Concept Deep Dive: Buffer Overflows Explained for Beginners"
date: 2026-02-26 08:00:00 +0300
categories: [Cybersecurity, Security Concepts]
tags: [buffer overflow, memory corruption, exploit development, c programming, blue team, vulnerability research, beginner]
author: Ongalo Glenn
description: A beginner-friendly deep dive into buffer overflows — what they are, how memory works, how attackers exploit them, and how defenders detect and prevent them.
---

## Introduction

Buffer overflows are one of the oldest and most famous vulnerability classes in cybersecurity. They have been behind some of the most devastating attacks in history — from the **Morris Worm of 1988**, one of the first internet worms, to the **WannaCry ransomware attack of 2017** which brought down hospitals and organisations worldwide.

Yet despite their age, buffer overflows remain relevant today. Understanding them is a rite of passage for security professionals — whether you are on the offensive side writing exploits or on the defensive side building detections and reviewing code.

In this post I will explain buffer overflows from the ground up, assuming no prior knowledge. By the end you will understand how memory works, why overflows happen, how attackers exploit them, and how defenders protect against them.

---

## Part 1: Understanding Memory — The Foundation

Before we can understand buffer overflows, we need to understand how a program uses memory when it runs.

When you launch a program, the operating system allocates memory for it. That memory is divided into distinct regions:

```
High Memory Addresses
┌─────────────────────┐
│        Stack        │  ← Local variables, function calls
├─────────────────────┤
│          ↓          │  Stack grows downward
│                     │
│          ↑          │  Heap grows upward
├─────────────────────┤
│        Heap         │  ← Dynamically allocated memory (malloc)
├─────────────────────┤
│        BSS          │  ← Uninitialised global variables
├─────────────────────┤
│        Data         │  ← Initialised global variables
├─────────────────────┤
│        Text         │  ← The actual program code (read-only)
└─────────────────────┘
Low Memory Addresses
```

For buffer overflows, the most important region is the **Stack**.

---

## Part 2: The Stack — Where the Magic (and the Danger) Happens

The stack is a region of memory that works like a stack of plates — you can only add to the top or remove from the top. This is called **LIFO** (Last In, First Out).

Every time your program calls a function, the system creates a **stack frame** for it. A stack frame contains:

- **Local variables** — variables declared inside the function
- **Saved Base Pointer (SBP)** — helps the function know where the previous frame starts
- **Return Address** — the memory address to jump back to when the function finishes

Here is a simple C program:

```c
#include <stdio.h>

void greet() {
    char name[10];  // buffer that holds 10 characters
    printf("Enter your name: ");
    gets(name);     // reads input into the buffer
    printf("Hello, %s!\n", name);
}

int main() {
    greet();
    return 0;
}
```

When `greet()` is called, the stack looks like this:

```
┌─────────────────────┐  ← Top of stack (lower address)
│   name[10]          │  10 bytes for our buffer
├─────────────────────┤
│   Saved Base Ptr    │  4 bytes
├─────────────────────┤
│   Return Address    │  4 bytes ← "go back to main() after greet() finishes"
└─────────────────────┘  ← Bottom of stack frame (higher address)
```

The **Return Address** is the critical piece. It tells the CPU where to continue execution after the function finishes. If an attacker can control that value — they control where the program goes next.

---

## Part 3: What is a Buffer?

A **buffer** is simply a fixed-size block of memory used to temporarily store data. Think of it like a glass of water — it has a fixed capacity.

```c
char name[10];  // This buffer can hold exactly 10 characters
```

This reserves exactly 10 bytes. If you try to pour 20 bytes into a 10-byte buffer — the extra bytes don't disappear. They spill over into adjacent memory regions. That spill is a **buffer overflow**.

---

## Part 4: The Overflow — What Actually Happens

Let's go back to our vulnerable program. The dangerous function is `gets()` — it reads user input with **no length checking whatsoever**. It will keep reading until it sees a newline character, no matter how much data the user provides.

Normal input — 5 characters:

```
User types: Glenn

Stack:
┌─────────────────────┐
│ G l e n n \0 _ _ _ _│  name[10] — fits perfectly, unused bytes zeroed
├─────────────────────┤
│   Saved Base Ptr    │  unchanged
├─────────────────────┤
│   Return Address    │  unchanged — program returns to main() normally
└─────────────────────┘
```

Malicious input — 20 characters:

```
User types: AAAAAAAAAABBBBCCCCDDDD

Stack:
┌─────────────────────┐
│ A A A A A A A A A A │  name[10] — completely filled
├─────────────────────┤
│ B B B B             │  Saved Base Ptr — OVERWRITTEN with B's
├─────────────────────┤
│ C C C C             │  Return Address — OVERWRITTEN with C's
└─────────────────────┘
```

When `greet()` finishes, the CPU tries to jump to the return address — but the return address is now `CCCC`, which is not a valid memory location. The program crashes.

**That crash is the overflow.** Now here is the key insight: instead of filling the return address with garbage, what if an attacker fills it with the address of their own malicious code?

---

## Part 5: Turning a Crash Into an Exploit

A skilled attacker does not just crash the program. They craft their input precisely to:

1. **Fill the buffer** with padding
2. **Overwrite the return address** with the address of their malicious code
3. **Include shellcode** — small machine code instructions that do something harmful

The payload looks like this:

```
[PADDING - fills the buffer exactly]
[NEW RETURN ADDRESS - points to the shellcode]
[SHELLCODE - the malicious instructions to execute]
```

When the function returns, instead of going back to `main()`, the CPU jumps directly to the shellcode. The attacker now has code execution.

**What can shellcode do?**
- Open a reverse shell — giving the attacker command line access to the system
- Add a new admin user
- Download and execute malware
- Disable security tools

This is why buffer overflows are so dangerous — they can lead to **complete system compromise**.

---

## Part 6: A Real Example — The Morris Worm (1988)

The Morris Worm was one of the first pieces of malware to spread across the internet. It exploited a buffer overflow in the Unix `fingerd` daemon — a service that provided user information.

The worm sent a specially crafted request that overflowed a buffer in the daemon, overwrote the return address with shellcode, and used the resulting shell access to spread itself to other machines. Within 24 hours it had infected thousands of Unix systems — roughly 10% of the internet at the time.

The Morris Worm demonstrated for the first time that a single memory safety bug could have catastrophic, self-propagating consequences. Thirty-eight years later, the lesson still applies.

---

## Part 7: Types of Buffer Overflows

### Stack-Based Buffer Overflow
The classic type we have been discussing. Overflows a buffer on the stack to overwrite the return address. Most common and most well-understood.

### Heap-Based Buffer Overflow
Overflows a buffer allocated on the heap (dynamic memory via `malloc`). More complex to exploit because the heap does not contain return addresses — attackers instead corrupt heap metadata or function pointers.

### Off-By-One Overflow
A subtle variant where the overflow is exactly one byte beyond the buffer boundary. Often caused by incorrect loop conditions:

```c
// Bug: loop should be i < 10, not i <= 10
for (int i = 0; i <= 10; i++) {
    buffer[i] = input[i];  // writes 11 bytes into a 10-byte buffer
}
```

One byte is enough to corrupt the saved base pointer and potentially redirect execution.

### Format String Vulnerabilities
Technically a separate class but closely related. Misuse of `printf()` without a format specifier allows attackers to read and write arbitrary memory:

```c
// Vulnerable
printf(user_input);

// Safe
printf("%s", user_input);
```

---

## Part 8: Defences Against Buffer Overflows

Modern operating systems and compilers have implemented multiple layers of protection. Understanding them is essential for both attackers and defenders.

### 1. Stack Canaries
A **canary** is a random value placed on the stack between the buffer and the return address. Before a function returns, it checks whether the canary has been modified. If it has — an overflow occurred — and the program terminates safely.

```
┌─────────────────────┐
│   buffer[10]        │
├─────────────────────┤
│   CANARY VALUE      │  ← random, checked before return
├─────────────────────┤
│   Saved Base Ptr    │
├─────────────────────┤
│   Return Address    │
└─────────────────────┘
```

To bypass a canary, an attacker needs to either leak the canary value first or find a way to overwrite it with the correct value.

**Enabled by default** in GCC with the `-fstack-protector` flag.

### 2. ASLR — Address Space Layout Randomisation
ASLR randomises the memory addresses of the stack, heap, and libraries every time a program runs. An attacker cannot hardcode the address of their shellcode because it will be in a different location each execution.

```
Run 1: Stack at 0x7fff3a2b0000
Run 2: Stack at 0x7fff8c1d0000
Run 3: Stack at 0x7fff1f4e0000
```

**Enabled by default** in Linux, Windows, and macOS.

Bypass techniques exist (memory leaks to defeat ASLR) but significantly raise the bar for exploitation.

### 3. DEP / NX — Data Execution Prevention / No-Execute
Marks memory regions as either writable OR executable, but never both. The stack can be written to but not executed. If an attacker places shellcode on the stack, the CPU will refuse to execute it.

**Enabled by default** on modern hardware and operating systems.

Attackers bypass this using **Return Oriented Programming (ROP)** — chaining together small snippets of existing executable code rather than injecting new shellcode.

### 4. Safe Functions
Many C functions that caused historical overflows have safe alternatives:

| Dangerous | Safe Alternative |
|---|---|
| `gets()` | `fgets()` |
| `strcpy()` | `strncpy()` |
| `strcat()` | `strncat()` |
| `sprintf()` | `snprintf()` |

Modern compilers warn about dangerous functions. Using safe alternatives with explicit length limits is one of the simplest preventative measures.

### 5. Memory-Safe Languages
Languages like **Rust**, **Go**, and modern **C++** perform automatic bounds checking — attempting to write beyond a buffer's end results in a runtime error or panic, not a silent overflow.

Python, Java, JavaScript, and most high-level languages are not vulnerable to buffer overflows by design — the runtime handles memory management automatically.

---

## Part 9: What SOC Analysts Need to Know

As a SOC analyst you are unlikely to write exploits — but you absolutely need to detect and respond to them.

**What buffer overflow exploitation looks like in logs and traffic:**

- **Crashes and core dumps** — repeated application crashes on the same process, especially a network-facing service, are a red flag. A skilled attacker may crash the service multiple times while fine-tuning their exploit.
- **IDS/IPS signatures** — network intrusion detection systems have signatures for common overflow payloads, including NOP sleds (long sequences of `0x90` bytes used to pad shellcode).
- **Unusual child processes** — a web server or database spawning `cmd.exe` or `/bin/sh` is a strong indicator of exploitation. This is exactly the kind of parent-child process relationship that Event ID 4688 and EDR tools flag.
- **Outbound connections from unexpected processes** — if `apache.exe` suddenly opens a connection to an external IP on port 4444 (common Metasploit reverse shell port), something is very wrong.
- **Memory protection alerts** — Windows Defender, CrowdStrike, and other EDR tools generate alerts when DEP/NX violations occur or when ASLR bypass techniques are detected.

**MITRE ATT&CK mapping:**
- T1203 — Exploitation for Client Execution
- T1068 — Exploitation for Privilege Escalation
- T1190 — Exploit Public-Facing Application

---

## Part 10: Testing It Yourself — Safely

The best way to understand buffer overflows is to practice in a safe, controlled environment.

**Recommended resources:**

- **Hack The Box Academy** — Buffer Overflow module walks through exploitation step by step
- **TryHackMe** — "Buffer Overflow Prep" room is excellent for beginners
- **Protostar** — a classic vulnerable VM designed specifically for learning exploitation
- **GDB** — the GNU Debugger is your essential tool for watching the stack in real time

**Basic tools:**
```bash
# Compile without protections for learning purposes
gcc -fno-stack-protector -z execstack -o vuln vuln.c

# Debug with GDB
gdb ./vuln

# Generate pattern to find exact overflow offset
python3 -c "print('A' * 100)"
```

> ⚠️ Only ever practice exploitation on systems you own or have explicit written permission to test. Exploiting systems without authorisation is illegal regardless of intent.

---

## Summary

| Concept | Key Point |
|---|---|
| Buffer | Fixed-size block of memory |
| Stack | Memory region holding local variables and return addresses |
| Overflow | Writing beyond a buffer's boundary into adjacent memory |
| Return Address | The CPU's "go back here" pointer — the attacker's target |
| Shellcode | Malicious machine code injected and executed via overflow |
| Canary | Random value detecting stack corruption before function return |
| ASLR | Randomises memory addresses to break hardcoded exploit addresses |
| DEP/NX | Prevents execution of data regions like the stack |
| ROP | Bypass technique chaining existing code snippets instead of shellcode |

---

## Final Thoughts

Buffer overflows are the perfect example of why security matters at every level — from the language you write code in, to the compiler flags you use, to the operating system protections you enable. A single missing bounds check can hand an attacker the keys to your entire system.

As I continue building toward my SOC Analyst role, understanding attack techniques like this shapes how I think about detections. Knowing what an overflow exploit looks like from the attacker's side makes me a sharper analyst when I see suspicious process behaviour, unexpected network connections, or repeated application crashes in a production environment.

The best defenders understand how attackers think.

---

*Found this useful? Connect with me on [LinkedIn](https://www.linkedin.com/in/ongalo-glenn) or explore more posts on this site.*
