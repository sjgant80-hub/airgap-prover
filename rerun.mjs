#!/usr/bin/env node
// rerun.mjs — THE RE-RUN RAIL. Re-derive every committed fixture's verdict with
// the kernel and diff it against the committed expected.json, byte for byte.
// This is what "re-runs to the same result" means: the proof is reproducible by
// anyone, anywhere, from the pinned inputs. Exits non-zero on any drift.
//
// Usage: node rerun.mjs   (run in CI and from the live page's "re-run" button)

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { witnessEgress } from "./egress.mjs";

const fx = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const expected = JSON.parse(readFileSync(join(fx, "expected.json"), "utf8"));
const manifest = expected.__manifest;

let drift = 0;
let checked = 0;
for (const name of Object.keys(expected)) {
  if (name.startsWith("__")) continue;
  const buf = readFileSync(join(fx, name));
  const got = witnessEgress(buf, manifest);
  const same = JSON.stringify(got) === JSON.stringify(expected[name]);
  checked++;
  if (!same) drift++;
  console.log(
    `${same ? "re-derives" : "DRIFTED  "}  ${name.padEnd(20)} ${got.verdict}  (egress ${got.egressCount})`
  );
}

// Guard: a committed fixture with no expected entry would be a silent gap.
const pcaps = readdirSync(fx).filter((f) => f.endsWith(".pcap"));
for (const p of pcaps) {
  if (!(p in expected)) {
    console.error(`UNPINNED  ${p} has no expected.json entry`);
    drift++;
  }
}

if (drift === 0) {
  console.log(`\nOK — ${checked} fixtures re-derive to expected.json byte-identically.`);
  process.exit(0);
}
console.error(`\nFAIL — ${drift} drift(s). The pinned proof did not reproduce.`);
process.exit(1);
