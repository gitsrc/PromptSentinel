# Security Policy

> 安全披露政策 — PromptSentinel 是一款安全产品,我们对漏洞报告高度重视并保密处理。

PromptSentinel is a **prompt-security gateway** that sits in front of an LLM to
screen input, screen output, and harden the system prompt. Because it is a
security control that protects other systems, we treat vulnerability reports
with the seriousness they deserve and ask researchers to follow **coordinated
(responsible) disclosure**.

We are grateful to the security community. Acting in good faith under this
policy, you will not be subject to legal action from the project for your
research.

---

## Supported versions

Security fixes are provided for the **latest minor release line**. Older lines
receive fixes only for critical issues, at the maintainers' discretion. We follow
[Semantic Versioning](https://semver.org/); see [`CHANGELOG.md`](CHANGELOG.md)
for the current release.

| Version | Supported          |
| ------- | ------------------ |
| `1.x`   | :white_check_mark: Active — security fixes |
| `< 1.0` | :x: Pre-release, unsupported |

When a fix lands, it ships in a new patch release and is noted in the changelog.
We recommend always running the most recent patch of the active line.

---

## Reporting a vulnerability

**Please do _not_ open a public GitHub issue, pull request, or discussion for a
security vulnerability.** Public disclosure before a fix is available puts every
deployment at risk.

Use one of these **private** channels instead:

1. **GitHub Private Vulnerability Reporting (preferred).**
   Go to the repository's **Security** tab → **Report a vulnerability**
   (`https://github.com/gitsrc/PromptSentinel/security/advisories/new`).
   This opens a private advisory visible only to you and the maintainers.

2. **Email.** Send details to the maintainer at the address listed on the
   GitHub profile of [`gitsrc`](https://github.com/gitsrc). Use a subject line
   starting with `[PromptSentinel Security]`. If you wish to encrypt the report,
   request a PGP key in a first contact message containing no sensitive details.

### What to include

A good report lets us reproduce and triage quickly:

- **Affected component** — e.g. `service/app/engine.py`, a specific scanner, an
  SDK (`sdks/{python,javascript,go,java}`), or the Web Console.
- **Version / commit** you tested against.
- **Type of issue** — e.g. detection bypass (a malicious prompt the engine fails
  to flag), fail-open behavior, secrets/PII leak in output screening, auth
  bypass, denial of service, dependency CVE, container misconfiguration.
- **Reproduction steps** — a minimal payload or request. For a **detection
  bypass**, please include the exact input and the threat class (injection /
  jailbreak / system-prompt extraction / canary leak / protected-identifier or
  PII leak) so we can add it to the regression corpus.
- **Impact** — what an attacker gains.
- **Environment** — OS, Python version, deployment mode (rules-only vs. ML
  cascade), and whether any optional tier (`WITH_LLM_GUARD`, `use_llm_judge`)
  was enabled.

> **Do not include real secrets, customer data, or live PII in your report.**
> Redact or synthesize. PromptSentinel never logs prompt/response bodies by
> design — please uphold that same standard in your disclosure.

---

## Our response targets

We aim to respond on the following timeline (business days, best effort):

| Stage                                   | Target            |
| --------------------------------------- | ----------------- |
| **Acknowledge** receipt of your report  | within **3 days** |
| **Triage** — confirm/decline, set severity | within **7 days** |
| **Status updates** while we work        | at least **every 14 days** |
| **Fix & coordinated disclosure**        | typically **within 90 days** |

Severity is assessed using [CVSS v3.1](https://www.first.org/cvss/). Critical
issues (e.g. a broadly exploitable detection bypass or auth bypass) are
expedited. We will keep you informed and agree on a disclosure date together; if
an issue is being actively exploited, we may disclose sooner.

When a fix ships, we will (with your permission) credit you in the advisory and
release notes. We do not currently run a paid bug-bounty program.

---

## Scope

**In scope** — the code in this repository:

- the Guard service (`service/`) and its detection engine, scanners, and API;
- the four client SDKs (`sdks/`);
- the bundled Web Console (`portal/`);
- packaging, container images defined here, and CI configuration.

**Especially valuable** to us:

- **Detection bypasses** — inputs that evade injection / jailbreak /
  system-prompt-extraction detection, or outputs that leak a canary, protected
  identifier, secret, or PII past the output scanner.
- **Fail-open** behavior — any engine path that *allows* on error instead of
  failing closed.
- **Data-residency / privacy** regressions — anything that causes prompt or
  response bodies, secrets, or PII to be logged, persisted, or sent off-host.
- **Auth bypass** on the service bearer token, and SSRF/egress from the
  detection path.

**Out of scope:**

- **Content-safety / toxicity / moderation** gaps. By design, PromptSentinel's
  threat model is the **prompt layer** (injection, extraction, leak) — *not*
  content moderation. A "harmful but non-injecting" prompt slipping through is
  **not** a vulnerability here.
- Findings that require a malicious or already-compromised host, root on the
  box, or physical access.
- Reports from automated scanners with no demonstrated, reproducible impact.
- Vulnerabilities solely in a third-party LLM you place *behind* the gateway.
- Social engineering, spam, or volumetric DDoS without an amplification bug.

---

## Safe harbor

We consider security research conducted in line with this policy to be
authorized, in good faith, and beneficial. We will not pursue or support legal
action against you for accidental, good-faith violations, provided you:

- make a good-faith effort to avoid privacy violations, data destruction, and
  service disruption;
- only interact with systems/accounts you own or have explicit permission to
  test;
- give us a reasonable time to remediate before any public disclosure;
- do not exfiltrate more data than necessary to demonstrate the issue.

Thank you for helping keep PromptSentinel and its users safe.
