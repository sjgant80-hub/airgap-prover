// egress.test.mjs — every test is a real boundary the kernel must hold.
// Written to KILL witness mutants: each comparison / logical / equality op in
// egress.mjs has a test that flips its verdict when the operator is flipped.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  parsePcap,
  frameToIp,
  isLoopback,
  isLinkLocal,
  isMulticast,
  isUnspecified,
  inCidr,
  classify,
  witnessEgress,
  buildReport,
  THREAT_MODEL,
  ipToString,
  LOCAL,
  LINKLOCAL,
  MULTICAST,
  DECLARED,
  EGRESS,
} from "./egress.mjs";
import {
  v4,
  v6,
  ipv4Frame,
  ipv6Frame,
  arpFrame,
  vlanIpv4Frame,
  rawIpv4,
  sllIpv4Frame,
  sllIpv6Frame,
  bigIpv4Frame,
  pcap,
  pcapBE,
} from "./fixtures/frames.mjs";

const b4 = (s) => Uint8Array.from(v4(s));
const b6 = (s) => Uint8Array.from(v6(s));

// ---- isLoopback -------------------------------------------------------------
test("loopback v4: 127.* yes, 126/128 no (=== boundary)", () => {
  assert.equal(isLoopback(4, b4("127.0.0.1")), true);
  assert.equal(isLoopback(4, b4("127.255.255.255")), true);
  assert.equal(isLoopback(4, b4("126.0.0.1")), false);
  assert.equal(isLoopback(4, b4("128.0.0.1")), false);
});
test("loopback v6: ::1 yes, ::2 and 1:: no", () => {
  assert.equal(isLoopback(6, b6("0:0:0:0:0:0:0:1")), true);
  assert.equal(isLoopback(6, b6("0:0:0:0:0:0:0:2")), false);
  assert.equal(isLoopback(6, b6("1:0:0:0:0:0:0:1")), false);
});

// ---- isLinkLocal ------------------------------------------------------------
test("link-local v4: 169.254 yes, 169.253 and 168.254 no (&& both bytes)", () => {
  assert.equal(isLinkLocal(4, b4("169.254.0.5")), true);
  assert.equal(isLinkLocal(4, b4("169.253.0.5")), false);
  assert.equal(isLinkLocal(4, b4("168.254.0.5")), false);
});
test("link-local v6: fe80/febf yes, fec0 and fe00 no (/10 mask)", () => {
  assert.equal(isLinkLocal(6, b6("fe80:0:0:0:0:0:0:1")), true);
  assert.equal(isLinkLocal(6, b6("febf:0:0:0:0:0:0:1")), true);
  assert.equal(isLinkLocal(6, b6("fec0:0:0:0:0:0:0:1")), false);
  assert.equal(isLinkLocal(6, b6("fe00:0:0:0:0:0:0:1")), false);
});

// ---- isMulticast ------------------------------------------------------------
test("multicast v4: 224 and 239 yes, 223 and 240 no (>= && <=)", () => {
  assert.equal(isMulticast(4, b4("224.0.0.1")), true);
  assert.equal(isMulticast(4, b4("239.255.255.255")), true);
  assert.equal(isMulticast(4, b4("223.0.0.1")), false);
  assert.equal(isMulticast(4, b4("240.0.0.1")), false);
});
test("multicast v6: ff00 yes, fe00 no", () => {
  assert.equal(isMulticast(6, b6("ff02:0:0:0:0:0:0:1")), true);
  assert.equal(isMulticast(6, b6("fe00:0:0:0:0:0:0:1")), false);
});

// ---- isUnspecified ----------------------------------------------------------
test("unspecified: 0.0.0.0 and :: yes, anything else no", () => {
  assert.equal(isUnspecified(4, b4("0.0.0.0")), true);
  assert.equal(isUnspecified(4, b4("0.0.0.1")), false);
  assert.equal(isUnspecified(6, b6("0:0:0:0:0:0:0:0")), true);
  assert.equal(isUnspecified(6, b6("0:0:0:0:0:0:0:1")), false);
});

// ---- inCidr -----------------------------------------------------------------
test("inCidr v4 /24: inside yes, outside no", () => {
  assert.equal(inCidr(4, b4("10.9.9.1"), "10.9.9.0/24"), true);
  assert.equal(inCidr(4, b4("10.9.9.254"), "10.9.9.0/24"), true);
  assert.equal(inCidr(4, b4("10.9.10.1"), "10.9.9.0/24"), false);
});
test("inCidr v4 /25: partial-byte mask boundary (127 in, 128 out)", () => {
  assert.equal(inCidr(4, b4("10.0.0.127"), "10.0.0.0/25"), true);
  assert.equal(inCidr(4, b4("10.0.0.128"), "10.0.0.0/25"), false);
});
test("inCidr v4 /32: exact only", () => {
  assert.equal(inCidr(4, b4("10.9.9.1"), "10.9.9.1/32"), true);
  assert.equal(inCidr(4, b4("10.9.9.2"), "10.9.9.1/32"), false);
});
test("inCidr family mismatch is false, never a crash", () => {
  assert.equal(inCidr(6, b6("fd00:0:0:0:0:0:0:1"), "10.9.9.0/24"), false);
  assert.equal(inCidr(4, b4("10.9.9.1"), "fd00::/8"), false);
});
test("inCidr v6 /8 ULA: fd00 in, 2001 out", () => {
  assert.equal(inCidr(6, b6("fd00:0:0:0:0:0:0:1"), "fd00::/8"), true);
  assert.equal(inCidr(6, b6("2001:4860:0:0:0:0:0:1"), "fd00::/8"), false);
});

// ---- classify ---------------------------------------------------------------
test("classify: each class routed to the right label", () => {
  const dp = ["10.9.9.0/24"];
  assert.equal(classify(4, b4("127.0.0.1"), dp), LOCAL);
  assert.equal(classify(4, b4("169.254.1.1"), dp), LINKLOCAL);
  assert.equal(classify(4, b4("224.0.0.251"), dp), MULTICAST);
  assert.equal(classify(4, b4("10.9.9.7"), dp), DECLARED);
  assert.equal(classify(4, b4("8.8.8.8"), dp), EGRESS);
});
test("classify: with NO declared peers a public addr is egress; a LAN addr too", () => {
  assert.equal(classify(4, b4("8.8.8.8"), []), EGRESS);
  assert.equal(classify(4, b4("10.9.9.7"), []), EGRESS); // undeclared private still egresses the boundary
});

// ---- witnessEgress (the verdict) -------------------------------------------
const MF = { declaredPeers: ["10.9.9.0/24", "fd00::/8"] };

test("offline capture -> CLEAN, egressCount 0", () => {
  const buf = pcap([ipv4Frame("127.0.0.1"), ipv4Frame("10.9.9.1"), ipv4Frame("224.0.0.251")]);
  const r = witnessEgress(buf, MF);
  assert.equal(r.verdict, "CLEAN");
  assert.equal(r.egressCount, 0);
});
test("one phone-home packet -> CAUGHT, egressCount 1, flagged dst listed", () => {
  const buf = pcap([ipv4Frame("127.0.0.1"), ipv4Frame("8.8.8.8")]);
  const r = witnessEgress(buf, MF);
  assert.equal(r.verdict, "CAUGHT");
  assert.equal(r.egressCount, 1);
  assert.equal(r.egressFlows[0].dst, "8.8.8.8");
});
test("CLEAN vs CAUGHT hinges on exactly zero (=== 0 boundary)", () => {
  // zero egress is CLEAN; a single egress flips to CAUGHT — kills !== / <= mutants
  assert.equal(witnessEgress(pcap([ipv4Frame("10.9.9.1")]), MF).verdict, "CLEAN");
  assert.equal(witnessEgress(pcap([ipv4Frame("1.2.3.4")]), MF).verdict, "CAUGHT");
});
test("duplicate dsts are counted, not double-listed", () => {
  const buf = pcap([ipv4Frame("8.8.8.8"), ipv4Frame("8.8.8.8"), ipv4Frame("8.8.8.8")]);
  const r = witnessEgress(buf, MF);
  assert.equal(r.observed.length, 1);
  assert.equal(r.observed[0].count, 3);
  assert.equal(r.egressCount, 1);
});
test("ARP frames carry no IP: counted in totalFrames, excluded from ipFrames", () => {
  const buf = pcap([ipv4Frame("10.9.9.1"), arpFrame()]);
  const r = witnessEgress(buf, MF);
  assert.equal(r.totalFrames, 2);
  assert.equal(r.ipFrames, 1);
  assert.equal(r.verdict, "CLEAN");
});
test("observed list is sorted deterministically", () => {
  const buf = pcap([ipv4Frame("9.9.9.9"), ipv4Frame("1.1.1.1"), ipv4Frame("5.5.5.5")]);
  const r = witnessEgress(buf, MF);
  assert.deepEqual(r.observed.map((o) => o.dst), ["1.1.1.1", "5.5.5.5", "9.9.9.9"]);
});

// ---- frameToIp (link layer) -------------------------------------------------
test("frameToIp: Ethernet IPv4 and IPv6 decode the dst", () => {
  assert.equal(ipToString(4, frameToIp(1, Uint8Array.from(ipv4Frame("8.8.4.4"))).dst), "8.8.4.4");
  const i6 = frameToIp(1, Uint8Array.from(ipv6Frame("2001:4860:4860:0:0:0:0:8888")));
  assert.equal(ipToString(6, i6.dst), "2001:4860:4860:0:0:0:0:8888");
});
test("frameToIp: ARP / non-IP ethertype returns null", () => {
  assert.equal(frameToIp(1, Uint8Array.from(arpFrame())), null);
});
test("frameToIp: 802.1Q VLAN tag is unwrapped", () => {
  const info = frameToIp(1, Uint8Array.from(vlanIpv4Frame("8.8.8.8")));
  assert.equal(ipToString(4, info.dst), "8.8.8.8");
});
test("frameToIp: DLT_RAW (101) raw IP, no Ethernet", () => {
  const info = frameToIp(101, Uint8Array.from(rawIpv4("8.8.8.8")));
  assert.equal(ipToString(4, info.dst), "8.8.8.8");
});
test("frameToIp: unknown link type returns null", () => {
  assert.equal(frameToIp(999, Uint8Array.from(ipv4Frame("8.8.8.8"))), null);
});

// ---- parsePcap (container) --------------------------------------------------
test("parsePcap reads the exact record count (both endiannesses)", () => {
  const frames = [ipv4Frame("1.1.1.1"), ipv4Frame("2.2.2.2"), ipv4Frame("3.3.3.3")];
  assert.equal(parsePcap(pcap(frames)).length, 3);
  assert.equal(parsePcap(pcapBE(frames)).length, 3);
});
test("big-endian and little-endian pcaps yield the identical verdict", () => {
  const frames = [ipv4Frame("127.0.0.1"), ipv4Frame("8.8.8.8")];
  const le = witnessEgress(pcap(frames), MF);
  const be = witnessEgress(pcapBE(frames), MF);
  assert.deepEqual(le, be);
});
test("parsePcap: a truncated final record is dropped, not fabricated", () => {
  const full = pcap([ipv4Frame("1.1.1.1"), ipv4Frame("2.2.2.2")]);
  const cut = full.subarray(0, full.length - 10); // chop the last record's body
  assert.equal(parsePcap(cut).length, 1);
});
test("parsePcap: bad magic throws", () => {
  assert.throws(() => parsePcap(Buffer.from([0, 1, 2, 3, ...new Array(40).fill(0)])));
});
test("parsePcap: truncated global header throws", () => {
  assert.throws(() => parsePcap(Buffer.from([0xa1, 0xb2, 0xc3])));
});

// ---- ipToString -------------------------------------------------------------
test("ipToString formats v4 and v6", () => {
  assert.equal(ipToString(4, b4("8.8.8.8")), "8.8.8.8");
  assert.equal(ipToString(6, b6("fd00:0:0:0:0:0:0:1")), "fd00:0:0:0:0:0:0:1");
});

// ---- Linux SLL (DLT 113) decode ---------------------------------------------
test("frameToIp: Linux SLL IPv4 and IPv6 decode the dst", () => {
  assert.equal(ipToString(4, frameToIp(113, Uint8Array.from(sllIpv4Frame("8.8.8.8"))).dst), "8.8.8.8");
  const i6 = frameToIp(113, Uint8Array.from(sllIpv6Frame("2001:4860:4860:0:0:0:0:8888")));
  assert.equal(ipToString(6, i6.dst), "2001:4860:4860:0:0:0:0:8888");
});
test("SLL capture of a phone-home is CAUGHT", () => {
  const buf = pcap([sllIpv4Frame("127.0.0.1"), sllIpv4Frame("8.8.8.8")], 113);
  const r = witnessEgress(buf, MF);
  assert.equal(r.verdict, "CAUGHT");
  assert.equal(r.egressFlows[0].dst, "8.8.8.8");
});

// ---- CIDR parsing edges (the manifest is an input, so malformed must bite) ---
test("inCidr: a declared peer with NO slash means an exact /32 (or /128) match", () => {
  assert.equal(inCidr(4, b4("10.9.9.1"), "10.9.9.1"), true); // exact
  assert.equal(inCidr(4, b4("10.0.0.5"), "10.9.9.1"), false); // not the same /32, not a /10
});
test("inCidr v6 no-slash is a full /128, not a truncated prefix", () => {
  assert.equal(inCidr(6, b6("2001:4860:0:0:0:0:0:1"), "2001:4860:0:0:0:0:0:1"), true);
  assert.equal(inCidr(6, b6("2001:4860:0:0:0:0:0:1"), "2001:4860:0:0:0:0:0:2"), false);
});
test("inCidr: an octet of 255 is valid; 256 is rejected (not silently masked)", () => {
  assert.equal(inCidr(4, b4("10.0.0.255"), "10.0.0.255/32"), true);
  assert.equal(inCidr(4, b4("10.0.0.5"), "10.0.0.256/24"), false); // 256 invalid -> no match
});
test("inCidr v6: a group of ffff is valid; 1ffff is rejected (not masked down)", () => {
  assert.equal(inCidr(6, b6("ffff:0:0:0:0:0:0:1"), "ffff::/16"), true);
  // overflow must be REJECTED, not truncated to 0xffff and then matched:
  assert.equal(inCidr(6, b6("ffff:0:0:0:0:0:0:1"), "1ffff::/16"), false);
});
test("inCidr: a non-numeric v4 octet is rejected, not coerced to 0", () => {
  // "zz" -> NaN; if accepted it would mask to 0.0.0.0/8 and wrongly match 0.*.
  assert.equal(inCidr(4, b4("0.0.0.5"), "zz.0.0.0/8"), false);
});
test("inCidr: a non-hex v6 group is rejected, not coerced to 0", () => {
  // "zz" -> NaN; if accepted it would mask to ::/16 and wrongly match 0:*.
  assert.equal(inCidr(6, b6("0:0:0:0:0:0:0:1"), "zz::/16"), false);
});
test("inCidr v6 full 8-group form (no ::) parses and matches on the low byte", () => {
  assert.equal(inCidr(6, b6("2001:4860:0:0:0:0:0:1"), "2001:4860:0:0:0:0:0:0/112"), true);
  // low byte of the last matched group must be honoured (/32 compares bytes 0..3):
  assert.equal(inCidr(6, b6("2001:4861:0:0:0:0:0:1"), "2001:4860::/32"), false);
  assert.equal(inCidr(6, b6("2001:4860:9:9:9:9:9:9"), "2001:4860::/32"), true);
});
test("inCidr: a CIDR with too many v6 groups is rejected, not crashed", () => {
  assert.equal(inCidr(6, b6("2001:0:0:0:0:0:0:1"), "2001:0:0:0:0:0:0:0:0/64"), false);
});

// ---- large frames exercise multi-byte pcap length fields --------------------
test("a 300-byte frame parses correctly (multi-byte little-endian length field)", () => {
  const buf = pcap([bigIpv4Frame("8.8.8.8", 300)]);
  assert.equal(parsePcap(buf).length, 1);
  assert.equal(witnessEgress(buf, MF).egressFlows[0].dst, "8.8.8.8");
});

// ---- bad input is a clean error, not a stray TypeError ----------------------
test("non-bytes input throws a clean 'need bytes' error", () => {
  assert.throws(() => witnessEgress(null, MF), /need bytes/);
  assert.throws(() => parsePcap(42), /need bytes/);
});

// ---- pcap container boundaries ----------------------------------------------
test("a header-only pcap (24 bytes, no records) parses to an empty list", () => {
  assert.deepEqual(parsePcap(pcap([])), []);
});
test("a zero-body trailing record is still read (<= boundary of the record loop)", () => {
  const base = pcap([ipv4Frame("8.8.8.8")]);
  const withTrailer = Buffer.concat([base, Buffer.alloc(16)]); // 16-byte header, incl_len 0
  assert.equal(parsePcap(withTrailer).length, 2);
  assert.equal(witnessEgress(withTrailer, MF).verdict, "CAUGHT"); // the real frame still counts
});

// ---- buildReport (the re-runnable report) -----------------------------------
test("buildReport carries the verdict, provenance meta, and the threat model", () => {
  const buf = pcap([ipv4Frame("8.8.8.8")]);
  const r = buildReport(buf, MF, {
    workload: "offline-grow",
    capturedBy: "tcpdump on veth-host",
    pcapSha256: "deadbeef",
    pcapBytes: buf.length,
  });
  assert.equal(r.verdict, "CAUGHT");
  assert.equal(r.egressCount, 1);
  assert.equal(r.workload, "offline-grow"); // || default must not drop a real value
  assert.equal(r.capturedBy, "tcpdump on veth-host");
  assert.equal(r.pcapSha256, "deadbeef");
  assert.equal(r.pcapBytes, buf.length);
  assert.ok(r.threatModel.includes("BELOW this capture point"));
  assert.equal(r.threatModel, THREAT_MODEL);
});
test("buildReport defaults absent provenance to null, never undefined", () => {
  const r = buildReport(pcap([ipv4Frame("10.9.9.1")]), MF);
  assert.equal(r.verdict, "CLEAN");
  assert.equal(r.workload, null);
  assert.equal(r.pcapSha256, null);
  assert.equal(r.pcapBytes, null);
});

// ---- the committed fixtures re-derive (the re-run rail, in-process) ---------
test("committed fixtures re-derive to committed expected.json byte-identically", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const fx = join(here, "fixtures");
  const expected = JSON.parse(readFileSync(join(fx, "expected.json"), "utf8"));
  const manifest = expected.__manifest;
  for (const [name, want] of Object.entries(expected)) {
    if (name.startsWith("__")) continue;
    const buf = readFileSync(join(fx, name));
    const got = witnessEgress(buf, manifest);
    assert.deepEqual(got, want, `${name} drifted from expected.json`);
  }
});
