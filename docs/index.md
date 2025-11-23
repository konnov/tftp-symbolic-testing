---
title: "TFTP-Symbolic-Testing"
layout: default
---

# TFTP-Symbolic-Testing

<link rel="stylesheet" href="assets/style.css">

<div class="hero">
  <img src="assets/logo-tftp-symbolic-testing.png" alt="TFTP-Symbolic-Testing Logo" class="hero-logo" />

  <div class="hero-text">
    <h1>TFTP-Symbolic-Testing</h1>
    <p class="tagline">
      Retro-style but modern <span class="accent">symbolic testing</span> for TFTP servers.
    </p>

    <p class="hero-cta">
      GitHub repo:
      <a href="https://github.com/konnov/tftp-symbolic-testing" target="_blank">
        konnov/tftp-symbolic-testing
      </a>
    </p>
  </div>
</div>

---

## What is this?

**TFTP-Symbolic-Testing** is an experimental framework for testing
TFTP servers (such as classic `tftpd-hpa`) with **symbolic techniques**
and **systematic state-space exploration**.

Instead of relying only on hand-written test cases or blind fuzzing,
this project lets you:

- specify the **behaviors of the TFTP clients and the server**,
- systematically explore them with **symbolic search**, and
- check whether the **server behaviour matches the specification**.

Think of it as a **DIY lab** for breaking and understanding TFTP
implementations.

---

## When would I use it?

You might want to use this project if you:

- maintain or fork a **TFTP server** (e.g., embedded firmware, PXE boot),
- need to **regression-test** changes around:
  - timeouts and retransmissions,
  - option negotiation,
  - duplicate packets and reordering,
- want to experiment with **symbolic model checking** / **formal methods**
  on a real protocol implementation.

---

## How it roughly works

At a high level:

1. **Protocol specification.**  
   You describe a space of TFTP interactions (e.g., client/server
   actions, packet fields, timing choices).

2. **Symbolic exploration.**  
   A back-end engine explores many variants of those interactions,
   not by brute force, but symbolically / systematically.

3. **Concrete execution against the SUT**  
   For each interesting path, the framework drives a real TFTP server,
   running in a container or a controlled environment.

4. **Property checking**  
   It checks for things like:
   - unexpected server crashes or hangs,
   - surprising responses (e.g., incorrect error codes).

The goal is not to be yet another black-box fuzzer,
but to make **protocol-specific, structure-aware testing**
accessible and reusable.

---

## Quick start

For installation and usage details, see the main repository:

```sh
git clone https://github.com/konnov/tftp-symbolic-testing.git
cd tftp-symbolic-testing
```

Then follow instructions in the project's README.md for:

- prerequisites,
- running symbolic tests,
- pointing the harness at your own TFTP implementation.

> **💡 Tip:** If you use Docker, you can keep your SUT and the harness in
> separate containers connected via a user-defined network.
> This keeps runs reproducible and easy to script.

---

## Typical use cases

- **Comparing two TFTP implementations.**  
  Generate tests with one implementation.
  Then replay them against another to find divergences in behavior.

- **Hardening a legacy TFTP deployment.**  
  Before enabling TFTP in production (PXE boot, firmware updates),
  explore timeout/option combinations.

- **Teaching / research.**  
  Demonstrate symbolic testing on a protocol that is small enough
  to understand, yet non-trivial due to timeouts, retransmissions,
  and options.

---

## Status & contributions

This is a research / experimental project.
Ideas, bug reports, and contributions are welcome:

👉 [https://github.com/konnov/tftp-symbolic-testing](https://github.com/konnov/tftp-symbolic-testing)

If you're interested in consulting, bespoke test development,
or applying this approach to another protocol, feel free to reach out.

---

<div class="footer">
  <span>© {{ "now" | date: "%Y" }} Igor Konnov 2025</span>
  <span class="sep">•</span>
  <span>Made with love for logic and retro pixels.</span>
</div>