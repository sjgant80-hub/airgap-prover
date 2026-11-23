# airgap-prover

### ▶ Live page: https://sjgant80-hub.github.io/airgap-prover/

Run a workload in a **locked, egress-controlled network namespace**, witness its packets
**from below** the guest, and emit a **re-runnable report** that observed egress over the run
was zero — or catch the one that phoned home.

The verdict kernel on the live page is the **exact kernel** CI mutation-gates: press *re-run* and
it re-derives the verdicts from the pinned captures in your browser.

> **Sealed result** ([run](https://github.com/sjgant80-hub/airgap-prover/actions/runs/37352056238)):
> offline workload → **CLEAN** (egress 0), phone-home control → **CAUGHT** (egress → 8.8.8.8,
> never reached Google), both captures re-derive byte-identically on CI, locally, and in the
> browser. See [`SEAL.md`](SEAL.md).

---

## What it proves (and what it can't)

- **Proves:** over the capture window, **zero packets** crossed the host / network-namespace
  boundary to a routable destination that was **not declared**. Measured from **below** the guest
  — `tcpdump` on the host side of the veth — so the workload cannot edit packets the host already saw.
- **Does not:** it is **"observed egress zero under a stated vantage"**, not "proof of a
  negative". A kernel- or firmware-level implant **below** the capture point can move bytes it never
  sees. The answer is not to evict it (software on a chip can't) but to **move the capture point down
  and outside** — the vantage ladder below — and to **name** what stays out of reach.

## The vantage ladder — how far below the snooping you can witness

You can't evict a backdoor fused into silicon with software running on that silicon. So airgap-prover
doesn't claim to. It moves the **capture point** down and outside, layer by layer, and states exactly
what each vantage reaches and what it still cannot. Each rung pushes the witness below the one above.

| Vantage | Where the capture runs | Reaches below | Residual |
|---|---|---|---|
| `host-netns` | tcpdump on the host, **same machine** | the guest / app (L3) | an OS / firmware / ME implant **below** this point |
| `external-tap` | a **separate trusted device** on the physical link (mirror port / inline tap) | the OS, firmware **and** management engine — *if the bytes cross the tapped link* | a byte put on **no** tapped wire (hidden radio, RF side-channel) |
| `physical-airgap` | no network link exists; **no declared peers**, so any routable packet is CAUGHT | an implant the moment it tries to speak on a wire | emanation on **no** wire — RF/TEMPEST, hidden radios |
| *the residual* | — | — | **hardware's job**: remove the radios, Faraday-shield. We say so, not pretend. |

- **`host-netns`** is the measured, sealed run on CI today.
- **`external-tap`** and **`physical-airgap`** are **kernel-supported and fixture-proven** here (see
  `fixtures/airgap/`). A real external capture is a **two-machine hardware procedure**, documented — not a
  CI run — so this repo does **not** claim a live silicon-level measurement it cannot re-derive.
- **Air-gap mode** (`mode:"airgap"`, or `--airgap`) empties the declared-peer allowlist: on a node that
  is meant to have no network, **any** routable destination — even one a connected node would admit — is egress.
- **Not fooled:** a phone-home **positive control** (a socket to `8.8.8.8`) runs in the same sealed
  namespace and must report **CAUGHT**; the gate fails on any false-pass.

## The mechanism (Linux)

```
guest netns ──veth── host        host: no forwarding, no NAT
   │ runs the workload              │ tcpdump records every packet that crossed
   │ (offline grow, or phone-home)  │ the boundary → egress.mjs renders the verdict
```

1. The guest gets a veth pair + a default route, so it **could** reach out if it tried.
2. The host forwards/NATs **nothing**, so anything the guest sends dies at the boundary.
3. `tcpdump` on the host side captures it; the kernel classifies each destination
   (loopback / link-local / multicast / declared-peer / **egress**).
4. The report carries the capture's `sha256`, so the verdict **re-derives byte-identically**.

`ip netns` + `tcpdump` are Linux, so the real measured run happens on the **GitHub Actions runner**
— the **CI re-derivation is the un-forgeable proof**. See **[the live measurement on
CI](https://github.com/sjgant80-hub/airgap-prover/actions)** (the `sealed-captures` artifact holds
the real pcaps + reports).

## Run it

```bash
node --test                      # the kernel + page scripts against their falsifiable boundaries
node rerun.mjs                   # the re-run rail: fixtures re-derive to expected.json (incl. airgap/)
node build-page.mjs              # inline the real kernel + all 3 capture sets into index.html
node scripts/serve.mjs           # preview the live page locally

# the live measurement (Linux only):
sudo ./harness/run-namespace.sh offline   out
node cli.mjs out/offline.pcap   --manifest harness/manifest.json --assert CLEAN
sudo ./harness/run-namespace.sh phonehome out
node cli.mjs out/phonehome.pcap --manifest harness/manifest.json --assert CAUGHT

# air-gapped node (no declared peers) captured from an external tap:
#   --airgap  empties the allowlist · --vantage  labels the capture point + its threat model
node cli.mjs capture.pcap --manifest harness/manifest.json --airgap --vantage external-tap --assert CLEAN
```

## Files

| file | what it is |
|------|------------|
| `egress.mjs` | the kernel — pcap decode + egress classification + verdict + report (zero-dep, Node + browser) |
| `egress.test.mjs` | 48 boundary tests; every comparison/logical op has a killing test |
| `witness.egress.baseline.json` | 12 reviewed-equivalent mutants, each with a written reason |
| `cli.mjs` | thin I/O: pcap + manifest → report JSON, `--assert CLEAN\|CAUGHT` for CI |
| `rerun.mjs` | the re-run rail: committed fixtures re-derive to `expected.json` |
| `harness/run-namespace.sh` | the Linux namespace harness — measures from below |
| `workloads/` | `offline-grow.mjs` (representative offline) + `phone-home.mjs` (positive control) |
| `fixtures/` | deterministic synthetic captures + `expected.json` |
| `index.html` | kernel-backed live page (generated by `build-page.mjs`) |

## Trust rail & credit

- Mutation-gated with **[witness](https://sjgant80-hub.github.io/witness/)** (`sjgant80-hub/witness@v0.6`).
- The re-run rail (CI re-derives from pinned inputs) follows the pattern proven in
  **[fallforgemint](https://sjgant80-hub.github.io/fallforgemint/)**.
- Sibling: **[airgap](https://sjgant80-hub.github.io/airgap/)** — a zero-network-stack sound mesh
  (different idea, shared name).
- The way it states its claim — a null that is allowed to hold, a positive control so the test can
  lose, predictions committed before the measurement ([`SEAL.md`](SEAL.md)), and nothing claimed past
  what was observed — draws on **Gary W. Floyd, Lumiea Systems Research Division — ThunderStruck Service LLC — "Entropy-Address Equivalence as a Candidate Bridge to Spacetime Geometry," Working Note, September 2026. Open Defensive Prior Art (Creative Commons).** The prover, its kernel and harness are
  the estate's own work. See [`NOTICE`](NOTICE).

MIT · by Simon Gant · part of the [AI Native Solutions](https://www.ai-nativesolutions.com/) estate.
