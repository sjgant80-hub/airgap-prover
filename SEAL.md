# SEAL — airgap-prover

A seal is two commits: this prereg (the predictions, committed and CI-green BEFORE the
outcome is recorded), then the measurement (the actual CI verdicts recorded, re-derived).
This is so the claim cannot be fitted to the result after the fact.

## Prereg (commit 1) — predictions, UNMEASURED

Stated before reading any live CI run of this repo:

1. **Offline workload → observed egress ZERO (CLEAN).** The representative offline workload
   (`workloads/offline-grow.mjs`, a prime-spine grow that makes no network calls), run inside
   the locked namespace, produces a host-side capture with no routable, undeclared destination.
   `cli.mjs --assert CLEAN` passes.

2. **Phone-home positive control → CAUGHT (0 false-pass).** The control
   (`workloads/phone-home.mjs`, a TCP connect to 8.8.8.8:443), run in the same sealed namespace,
   emits a SYN that the host-side capture records; the kernel flags it as egress.
   `cli.mjs --assert CAUGHT` passes. The packet never reaches Google (host does not forward/NAT).

3. **The report re-derives byte-identically from the pinned inputs.** The committed fixtures
   re-derive to `fixtures/expected.json` (`rerun.mjs`), and each live capture re-derives to the
   same verdict JSON on repeat kernel runs. Determinism holds across Node, CI, and the browser.

Threat-model caveat (stated up front, not a result): this observes egress at the host /
namespace boundary over the capture window. A kernel- or firmware-level implant below the capture
point defeats it. This is "observed egress zero under a stated threat model", not proof of a negative.

### Local, pre-push (Windows, Node v25) — the parts that run off-CI

- `node --test egress.test.mjs` → 48/48 pass.
- witness v0.6 `mutate egress.mjs` with baseline → CLEAN (97/109 killed, 12 reviewed-equivalent).
- `node rerun.mjs` → 3 fixtures re-derive to expected.json byte-identically.
- The live namespace run (`ip netns` + `tcpdump`) is Linux-only; it runs on the CI runner. UNMEASURED here.

## Measurement (commit 2) — recorded after the live CI run

<!-- filled in by commit 2 from the actual live-measure job -->
- Status: PENDING first CI run.
- CI run: <url>
- Sealed run 1 (offline): <CLEAN|CAUGHT>
- Sealed run 2 (phone-home): <CLEAN|CAUGHT>
- Re-derivation: <identical|drift>
- Real captures committed as fixtures: <names>
