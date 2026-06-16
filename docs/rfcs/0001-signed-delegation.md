# RFC-0001: Signed, scope-narrowing delegation for computeid-sdk

**Status:** Draft — Request for Comments (no code in this PR)

## Motivation

We're running a live cross-organization agent-to-agent (A2A) federation: an agent in
org A delegates a scoped task to an agent in org B. Each side must verify the *other*
side's delegation **without trusting the other side's servers**, and must enforce that
authority **only ever narrows** down the delegation chain.

`computeid-sdk` is the right home for this — it already owns passports, the
`AgentCapabilities` vocabulary, the trust registry (`PassportOffice`), audit, and
revocation. Three properties are missing for true cross-org verification. This RFC
proposes adding them **backwards-compatibly**, layered on the existing model.

## Non-goals / compatibility

- The SHA-256 fingerprint stays. An Ed25519 signature is **added** alongside it.
- Hosted issuance/registry/revocation stays. Verification becomes *additionally* possible
  **offline** using public keys resolved from the registry.
- Single-passport flows (`verify_action`, `@requires_passport`) are unchanged.

## Proposal

### 1. Ed25519 signing keys on passports
`AgentPassport.issue(...)` gains an opt-in Ed25519 keypair (software profile first; a
`key_anchor` slot leaves room for hardware/TPM later). The public key is published as an
OKP/Ed25519 JWK in the passport's public descriptor. Rationale: a SHA-256 fingerprint
cannot be verified by a third party; a signature can.

### 2. Scope-narrowing delegation receipts + chain
A `DelegationReceipt` is one signed hop: the issuing passport signs
`{iss, sub, prn, cap, iat, exp, chain_pos, prev}`, where `cap` is drawn from the existing
`AgentCapabilities` vocabulary. Invariants enforced at construction and re-checked at
verification: `cap ⊆ parent.cap`, `exp ≤ parent.exp`, `prev` = hash of the previous
receipt, monotonic `chain_pos`, and constant `prn` across the chain (cross-principal
contamination guard). This is the property `parent_agent_id` linkage alone does not give.

### 3. Offline gateway verifier
`verify_chain(encoded_chain, resolve, required_cap, ...) -> Verdict` — pure and offline
(only needs issuer public keys via `resolve`), returning typed machine reason codes
(`scope_widened`, `expired`, `broken_delegation`, `principal_drift`, `capability_missing`,
`revoked_agent`, `bad_signature`, …) plus the resolved principal and final capability set.
A request gateway calls this per call to gate access.

## How it's consumed

The delegating agent carries the encoded chain in a request header; the receiving side's
gateway calls `verify_chain` before granting access. Nothing requires the two orgs to
share infrastructure.

## Open questions for the maintainer

1. Placement: extend `computeid.py`, or a new `computeid/delegation.py` submodule?
2. `cap` representation: full `AgentCapabilities` dict, or a reduced capability-token list?
3. Revocation during verification: live registry lookup vs. a short-TTL cached revocation
   list for true offline operation?
4. Include the hardware-attestation (`key_anchor`) slot now, or defer it?

A reference implementation of all three sections already exists and is in use. If you're
open to the direction, I'll follow up with focused, reviewable PRs per section.
