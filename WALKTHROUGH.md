# Prospective-client walkthrough — airgap-prover sellable pass (2026-11-23)

Buyer personas opened the live page cold and raised objections; every one is answered ON the page.
Personas were run on the local sovereign model (Ollama qwen2.5:7b via FallCore) where it had capacity
(it saturated on concurrent calls — a local-hardware limit, no cloud fallback used); the remaining
persona reads and the gap triage were done here. No frontier fan-out.

## Personas & objections → fixes

**Board / procurement (skeptical of security vendors) — run on local qwen2.5:7b.**
1. "Proof of a negative is inherently unreliable." → The page never claims proof of a negative; added a
   line under the hero stating so and linking to the vantage ladder, which says exactly what is proved.
2. "An implant below the host vantage can still hide calls." → Already the core of the ladder; the
   external-tap rung is the stated fix. Added concrete two-machine reproduction steps so it is real, not a promise.
3. "Residual risk is hardware-dependent (RF/TEMPEST)." → Stated as the named residual (hardware/Faraday),
   now also in the risks card and the board line — answered, not buried.

**CISO (defence contractor).**
1. The strongest vantage (external-tap) was described but not shown reproducible. → Added the exact
   mirror-port / inline-TAP + `cli.mjs --vantage external-tap` procedure as a `<details>` under the ladder.
2. Exfiltration via a declared peer. → Added: a declared peer is an allowlist you choose and audit —
   egress to it is a decision on the record, not a blind spot; air-gap mode removes the allowlist entirely.

**Compliance auditor (ISO 27001 / NIST).**
1. Evidence vs certification confusion. → Compliance role card now says "evidence for your controls, NOT a
   certification of them — the judgement stays yours."
2. Which controls. → Named honestly (ISO 27001 A.8, NIST 800-53 SC-7 boundary protection) as the kind of
   evidence those reviews ask for, not a compliance claim.

**CFO (is the saving real).**
1. Default saving looks self-serving. → The calculator is driven by the buyer's own inputs; the basis line
   states the defaults are an illustrative floor, not a claim about them, and the figure is computed not typed.
2. Is ongoing cost really £0. → The cost kernel includes review hours + amortised setup, so "with the
   receipt" is a real non-zero number, shown beside the manual number — not a £0 claim.

## What this pass added over the first build
The first airgap-prover build shipped the proof and the honest threat model but no business case — a buyer
couldn't justify it to a board. This pass added the role-by-role brochure, a kernel-computed (buyer-driven)
cost case, the comparison table, security/GDPR/ownership/exit answers, and the board line — then hardened
them against five buyer personas. The check that now stops the gap: the sellable rule (every product ships
the brochure + a persona walkthrough before "done").
