#!/usr/bin/env node
// cli.mjs — thin I/O around the kernel. Reads a pcap + manifest, computes the
// provenance hashes (I/O), calls buildReport, prints the re-runnable report,
// and (with --assert) exits non-zero when the verdict is not what was expected.
//
// Usage:
//   node cli.mjs <capture.pcap> --manifest <manifest.json> \
//        [--workload NAME] [--capturedBy TEXT] [--assert CLEAN|CAUGHT] [--quiet]
//
// The report it prints is the product: it carries the sha256 of exactly the
// bytes that were observed, so anyone can re-run the kernel over the same pcap
// and derive the same verdict.

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { buildReport } from "./egress.mjs";

function arg(flag, def = null) {
  const i = process.argv.indexOf(flag);
  return i !== -1 && i + 1 < process.argv.length ? process.argv[i + 1] : def;
}
const has = (flag) => process.argv.includes(flag);

const pcapPath = process.argv[2];
if (!pcapPath || pcapPath.startsWith("--")) {
  console.error("usage: node cli.mjs <capture.pcap> --manifest <m.json> [--assert CLEAN|CAUGHT]");
  process.exit(2);
}

const manifestPath = arg("--manifest");
const manifest = manifestPath ? JSON.parse(readFileSync(manifestPath, "utf8")) : {};
const pcapBuf = readFileSync(pcapPath);
const pcapSha256 = createHash("sha256").update(pcapBuf).digest("hex");

const report = buildReport(pcapBuf, manifest, {
  workload: arg("--workload"),
  capturedBy: arg("--capturedBy"),
  pcapSha256,
  pcapBytes: pcapBuf.length,
});

if (!has("--quiet")) console.log(JSON.stringify(report, null, 2));

const expect = arg("--assert");
if (expect) {
  if (report.verdict === expect) {
    console.error(`[airgap-prover] OK: verdict ${report.verdict} == expected ${expect}`);
    process.exit(0);
  } else {
    console.error(`[airgap-prover] FAIL: verdict ${report.verdict} != expected ${expect}`);
    if (report.egressFlows.length) {
      console.error("  egress observed to:", report.egressFlows.map((f) => f.dst).join(", "));
    }
    process.exit(1);
  }
}
