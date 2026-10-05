// fixtures/make.mjs — build DETERMINISTIC pcap fixtures + expected verdicts.
//
// These are SYNTHETIC captures: they encode known Ethernet/IP frames with fixed
// bytes so the decoder (egress.mjs) and the re-run rail are reproducible and
// hashable. They are NOT the live proof — the live proof is the CI namespace
// job that captures REAL host-observed packets (harness/run-namespace.sh).
// These fixtures prove the decoder is correct and the verdict re-derives.
//
// Run: node fixtures/make.mjs   (regenerates the .pcap files + expected.json)

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { witnessEgress } from "../egress.mjs";
import { ipv4Frame, ipv6Frame, pcap } from "./frames.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

const MANIFEST = { declaredPeers: ["10.9.9.0/24", "fd00::/8"] };

const SCENARIOS = {
  // A representative OFFLINE run: chatter to loopback, a declared local peer,
  // and link-local/multicast noise (mDNS). No routable egress. -> CLEAN.
  "offline.pcap": [
    ipv4Frame("127.0.0.1"),
    ipv4Frame("10.9.9.1"),
    ipv4Frame("224.0.0.251"),
    ipv4Frame("169.254.0.5"),
    ipv6Frame("fd00:0:0:0:0:0:0:1"),
    ipv6Frame("0:0:0:0:0:0:0:1"),
  ],
  // The POSITIVE CONTROL: offline chatter PLUS one SYN to a public address
  // (8.8.8.8) and one to a public v6. The prover MUST catch these.
  "phonehome.pcap": [
    ipv4Frame("127.0.0.1"),
    ipv4Frame("10.9.9.1"),
    ipv4Frame("8.8.8.8"),
    ipv6Frame("2001:4860:4860:0:0:0:0:8888"),
  ],
  // Only declared-peer traffic -> CLEAN (proves the allowlist admits peers).
  "declared-peer.pcap": [ipv4Frame("10.9.9.1"), ipv4Frame("10.9.9.254")],
};

const expected = {};
for (const [name, frames] of Object.entries(SCENARIOS)) {
  const buf = pcap(frames);
  writeFileSync(join(HERE, name), buf);
  expected[name] = witnessEgress(buf, MANIFEST);
}
expected.__manifest = MANIFEST;
writeFileSync(join(HERE, "expected.json"), JSON.stringify(expected, null, 1) + "\n");

console.log("wrote", Object.keys(SCENARIOS).length, "pcap fixtures + expected.json");
for (const [name, v] of Object.entries(expected)) {
  if (name.startsWith("__")) continue;
  console.log(`  ${name}: ${v.verdict} (egress ${v.egressCount}/${v.observed.length} observed)`);
}
