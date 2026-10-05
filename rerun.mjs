#!/usr/bin/env node
// rerun.mjs — THE RE-RUN RAIL. Re-derive every pinned capture's verdict with the
// kernel and diff it against the committed expected.json, byte for byte. This is
// what "re-runs to the same result" means: reproducible by anyone, anywhere,
// from the pinned inputs. Exits non-zero on any drift.
//
// It covers TWO proof sets:
//   fixtures/            — deterministic SYNTHETIC captures (prove the decoder)
//   fixtures/live/       — the REAL host-observed captures from a CI namespace run
//
// Usage: node rerun.mjs   (run in CI and behind the live page's "re-run" button)

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { witnessEgress } from "./egress.mjs";

const ROOT = dirname(fileURLToPath(import.meta.url));

const SETS = [
  { label: "synthetic", dir: join(ROOT, "fixtures") },
  { label: "live (real capture)", dir: join(ROOT, "fixtures", "live") },
];

let drift = 0;
let checked = 0;
for (const set of SETS) {
  const expPath = join(set.dir, "expected.json");
  if (!existsSync(expPath)) continue;
  const expected = JSON.parse(readFileSync(expPath, "utf8"));
  const manifest = expected.__manifest;
  console.log(`\n[${set.label}]  manifest declaredPeers=${JSON.stringify(manifest.declaredPeers)}`);
  for (const name of Object.keys(expected)) {
    if (name.startsWith("__")) continue;
    const got = witnessEgress(readFileSync(join(set.dir, name)), manifest);
    const same = JSON.stringify(got) === JSON.stringify(expected[name]);
    checked++;
    if (!same) drift++;
    console.log(
      `  ${same ? "re-derives" : "DRIFTED  "}  ${name.padEnd(16)} ${got.verdict}  (egress ${got.egressCount})`
    );
  }
  // every pinned pcap must have an expected entry — no silent gaps
  for (const p of readdirSync(set.dir).filter((f) => f.endsWith(".pcap"))) {
    if (!(p in expected)) {
      console.error(`  UNPINNED  ${p} has no expected.json entry`);
      drift++;
    }
  }
}

if (drift === 0) {
  console.log(`\nOK — ${checked} pinned captures re-derive to expected.json byte-identically.`);
  process.exit(0);
}
console.error(`\nFAIL — ${drift} drift(s). The pinned proof did not reproduce.`);
process.exit(1);
