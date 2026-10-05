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

Measured on the GitHub Actions runner (ubuntu-latest, `ip netns` + `tcpdump`,
Node 20). All three predictions held.

- Status: **MEASURED — all three predictions held.**
- CI run: https://github.com/sjgant80-hub/airgap-prover/actions/runs/37352056238 (proof-of-play, green)
- **Sealed run 1 (offline-grow): CLEAN** — 930 bytes captured, egress 0. The only
  traffic observed was IPv6 link-scoped multicast (MLD / router-solicitation / DAD:
  ff02::16, ff02::2, ff02::1:ff…), all classified multicast → allowed. The workload
  made no network calls. `OK: verdict CLEAN == expected CLEAN`.
- **Sealed run 2 (phone-home): CAUGHT** — 1306 bytes captured, egress 1 → **8.8.8.8**.
  The SYN was emitted onto the veth and caught at the boundary; it timed out and never
  reached Google (host forwards/NATs nothing). `OK: verdict CAUGHT == expected CAUGHT`.
  0 false-pass.
- **Re-derivation: identical.** Both captures re-derive to the same verdict on repeat
  kernel runs on the runner, re-derive again locally on Windows (Node v25), and again
  in-browser on the live page. Cross-platform, byte-identical.
- **Real captures committed as fixtures:** `fixtures/live/offline.pcap`,
  `fixtures/live/phonehome.pcap` (+ `fixtures/live/expected.json`), so the exact
  host-observed bytes re-derive forever via `rerun.mjs` and the live page's re-run button.

Honest one-line: this proves **observed egress zero at the host / network-namespace
boundary over the run** (and catches the one that tried). It does **not** see a
kernel/firmware implant below that boundary — L3/L2 are the next layers down.
