// fixtures/make.mjs — build DETERMINISTIC pcap fixtures + expected verdicts.
//
// These are SYNTHETIC captures: they encode known Ethernet/IP frames with fixed
// bytes so the decoder (egress.mjs) and the re-run rail are reproducible and
// hashable. They are NOT the live proof — the live proof is the CI namespace
// job that captures REAL host-observed packets (harness/run-namespace.sh).
// These fixtures prove the decoder is correct and the verdict re-derives.
//
// Run: node fixtures/make.mjs   (regenerates the .pcap files + expected.json)

import { writeFileSync, mkdirSync } from "node:fs";
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

// ---- AIR-GAP set ------------------------------------------------------------
// A node meant to have NO network declares NO peers (mode: "airgap"), so ANY
// routable packet is egress — INCLUDING a destination that a connected node
// would wave through as a declared peer. This is the stricter stance the
// air-gapped / external-tap vantage uses. Its own dir + manifest so the main
// set stays byte-identical.
const AIRGAP_DIR = join(HERE, "airgap");
const AIRGAP_MANIFEST = { mode: "airgap", declaredPeers: ["10.9.9.0/24"] };
const AIRGAP_SCENARIOS = {
  // Truly silent: loopback + link-local only. Nothing routable. -> CLEAN.
  "airgap-silent.pcap": [
    ipv4Frame("127.0.0.1"),
    ipv4Frame("169.254.0.5"),
    ipv6Frame("0:0:0:0:0:0:0:1"),
  ],
  // The air-gap positive control: a beacon to 10.9.9.1 (which a CONNECTED node
  // would admit as a declared peer) PLUS a covert public host. On an air-gapped
  // node BOTH are egress — the declared allowlist does not apply. -> CAUGHT.
  "airgap-leak.pcap": [
    ipv4Frame("127.0.0.1"),
    ipv4Frame("10.9.9.1"),
    ipv4Frame("185.220.101.5"),
  ],
};
mkdirSync(AIRGAP_DIR, { recursive: true });
const expectedAirgap = {};
for (const [name, frames] of Object.entries(AIRGAP_SCENARIOS)) {
  const buf = pcap(frames);
  writeFileSync(join(AIRGAP_DIR, name), buf);
  expectedAirgap[name] = witnessEgress(buf, AIRGAP_MANIFEST);
}
expectedAirgap.__manifest = AIRGAP_MANIFEST;
writeFileSync(join(AIRGAP_DIR, "expected.json"), JSON.stringify(expectedAirgap, null, 1) + "\n");

const all = { ...expected, ...expectedAirgap };
console.log(
  "wrote",
  Object.keys(SCENARIOS).length + Object.keys(AIRGAP_SCENARIOS).length,
  "pcap fixtures (main + airgap) + expected.json x2"
);
for (const [name, v] of Object.entries(all)) {
  if (name.startsWith("__")) continue;
  console.log(`  ${name.padEnd(20)}: ${v.verdict} (egress ${v.egressCount}/${v.observed.length} observed)`);
}
