# Security Policy

## Reporting a Vulnerability

Please do not open a public issue, discussion, or pull request for a suspected vulnerability.

Use the **Report a vulnerability** button on this repository's **Security** tab. The direct private form is:

https://github.com/arkade-os/arkd/security/advisories/new

Keep technical details in the private advisory. Do not include seed phrases, private keys, production credentials, live user data, or funds in a report. Do not test against accounts, funds, or deployments you do not own or have explicit permission to test.

We aim to acknowledge a new report within 2 business days. If you do not receive a response, add a comment to the private advisory. If GitHub reports that private reporting is unavailable, email security@arklabs.to without technical details and ask for a private channel.

## System and Scope

This policy covers **arkade-os/arkd**: the Arkade operator backend that coordinates VTXOs, batching, settlement, liquidity, and the public server API.

The policy applies to the source in this public repository, release artifacts and packages built from it, and services operated by Ark Labs or Arkade OS from an unmodified release. It also covers a vulnerability in a dependency when the issue creates an exploitable path through this repository's code or a supported deployment.

Documented alpha, testnet, or unaudited status is severity context, not a blanket exclusion. A testnet-only issue is still relevant when it exposes a flaw that can reach a supported mainnet or published release path.

## Threat Model and Trust Boundaries

This repository uses the **Protocol and runtime** profile. The security boundary includes user signing authority, VTXO and settlement state, operator liquidity, contract source and compiled artifacts, VM evaluation, replay protection, and recovery from unknown outcomes.

Assets include private keys and signing authority, funds and VTXOs, settlement and payment state, contract source and compiled artifacts, service credentials, enclave or MPC material, user data, and release integrity.

Attacker-controlled inputs include network traffic, RPC, HTTP, and gRPC input, invoices and webhook payloads, relay and peer messages, contract source and artifacts, repository metadata, build inputs, dependencies, and stored state created by another participant.

Users control their own keys. Remote servers, operators, solvers, plugins, peers, RPC providers, and relayed messages are untrusted unless a protocol step verifies them. A valid signature, a successful HTTP response, a relayed message, or a valid quote is not authorization by itself. Mocks, fixtures, regtest, and testnet behavior do not establish production safety.

## Security Invariants

- No spend path may move funds without the signatures, timelocks, asset rules, and other conditions required by the protocol.
- VTXO, batch, commitment, exit, renewal, and recovery transitions must conserve value and reject wrong-network, wrong-outpoint, duplicate, and replayed transactions.
- The VM, compiler, and emulator must preserve script semantics, reject malformed or unbounded inputs, and never gain an unintended host-level execution path.
- Compiled artifacts and generated bindings must correspond to the reviewed source and must not silently weaken covenant or unilateral-exit constraints.
- Settlement and recovery state must be idempotent. A timeout, restart, or unknown outcome must not create a second spend, credit, batch, or payout.

## Reportable Findings and Severity Context

A reportable finding is a practical violation of confidentiality, integrity, availability, authorization, fund safety, key safety, settlement correctness, or release integrity that is reachable in source, a supported deployment, or a published artifact.

Raise severity when reachability is unauthenticated, the issue affects many users or deployments, funds or keys can be taken or frozen, an attacker can turn an unknown outcome into a duplicate spend or credit, or the issue enters a published package or release artifact.

- **Critical:** theft or loss of funds or keys at scale, unauthenticated signing or spending, a covenant or VM bypass across users, enclave or MPC secret extraction, or broad compromise of a published package.
- **High:** practical loss of one user's or one merchant's funds, repeatable double settlement or credit, authorization bypass to a privileged operation, persistent production denial of service, or a supply-chain flaw in a supported release.
- **Medium:** bounded denial of service, cross-user information disclosure, privilege escalation without direct fund impact, or a security-control bypass with realistic but limited preconditions.
- **Low:** a demonstrated information leak, missing hardening, or defense-in-depth gap without a practical path to meaningful impact.

These are context for prioritization, not a requirement that reporters assign the final severity.

## Out of Scope, Exclusions, and Accepted Risk

- A custom fork or modified deployment that is not operated by Ark Labs or Arkade OS.
- A vulnerability only in a third-party dependency, when it cannot be exploited through this repository or a supported deployment. Report that dependency upstream as well.
- Feature requests, non-security bugs, and reports without a concrete security impact.
- Social engineering, physical access, or a report that requires an already compromised device or credential, unless the compromise exposes an upstream weakness.
- Public disclosure before we have coordinated a fix and disclosure date.
- Spam, automated low-signal reports, leaked secrets unrelated to this repository, and requests for payment in exchange for withholding disclosure.

We will not treat an inference or an undocumented assumption about a deployment as an accepted risk. A known limitation becomes an accepted risk only after review and documentation by the repository owner.

## Remediation and Coordinated Disclosure

We aim to remediate a confirmed vulnerability within 90 business days from acknowledgement. Severity, dependency constraints, protocol compatibility, and coordinated testing can change that target; we will explain material delays in the private advisory.

We will keep the reporter informed in the private advisory, work with the reporter on a suitable public disclosure date after remediation, and coordinate credit. If exploitation creates an immediate risk to users, we may publish mitigations before the full advisory.

## Reporting Template

Use the following structure in the private advisory:

```text
* Summary:
* Repository, release, commit, or deployment:
* Security impact:
* Preconditions and attacker capability:
* Steps to reproduce and proof of concept:
* Affected keys, funds, data, or transactions:
* Suggested severity and reasoning:
* Suggested mitigation:
* Credit preference:
```

Redact secrets, private keys, seed phrases, live credentials, addresses not controlled by the reporter, and personal data.
