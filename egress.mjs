// egress.mjs — the airgap-prover KERNEL (zero-dep, Node + browser).
//
// Given the raw bytes of a packet capture (pcap) observed at the host /
// network-namespace boundary while a workload ran, and a manifest of DECLARED
// peers, render a re-runnable verdict: was any egress observed to a routable
// destination that was NOT declared?
//
// This is the whole point of "measure from BELOW": the capture is taken by the
// host, outside the guest. The guest cannot edit packets the host already saw.
// The kernel only READS the observed bytes — it never touches the network.
//
// Honest threat model (also on the tin): this observes egress at the host /
// namespace boundary over the capture window. A kernel- or firmware-level
// implant BELOW this capture point could move bytes this never sees. That is
// why L3 (OS) and L2 (firmware) are the next layers down — adopt-and-prove,
// not claimed here. This is "observed egress zero under a stated threat model",
// never "proof of a negative".

// ---- pcap container ---------------------------------------------------------

// Magic read big-endian off disk. 0xa1b2c3d4 means the file's fields are
// stored BIG-endian; 0xd4c3b2a1 means they are stored LITTLE-endian (the bytes
// were swapped on write). The *3c4d / 4d3c* variants are nanosecond-resolution.
const MAGIC_BE = 0xa1b2c3d4; // fields big-endian
const MAGIC_LE = 0xd4c3b2a1; // fields little-endian
const MAGIC_NS_BE = 0xa1b23c4d; // fields big-endian, ns
const MAGIC_NS_LE = 0x4d3cb2a1; // fields little-endian, ns

const DLT_EN10MB = 1; // Ethernet (veth capture)
const DLT_RAW = 101; // raw IP
const DLT_LINUX_SLL = 113; // Linux cooked (tcpdump -i any)

// Read a pcap buffer into a flat list of { linkType, frame } records.
// `buf` is a Uint8Array / Node Buffer. Throws only on a truncated global
// header; a truncated record stops iteration (tcpdump can be SIGKILLed mid
// write — a half-record is not a packet, so we stop, we do not invent one).
export function parsePcap(buf) {
  const u8 = toU8(buf);
  if (u8.length < 24) throw new Error("pcap: truncated global header");
  const magic = rd32be(u8, 0);
  let le;
  if (magic === MAGIC_LE || magic === MAGIC_NS_LE) le = true;
  else if (magic === MAGIC_BE || magic === MAGIC_NS_BE) le = false;
  else throw new Error("pcap: bad magic 0x" + magic.toString(16));
  const r32 = le ? rd32le : rd32be;
  const linkType = r32(u8, 20);
  const records = [];
  let off = 24;
  while (off + 16 <= u8.length) {
    const inclLen = r32(u8, off + 8);
    const start = off + 16;
    const end = start + inclLen;
    if (end > u8.length) break; // truncated final record — stop, do not fabricate
    records.push({ linkType, frame: u8.subarray(start, end) });
    off = end;
  }
  return records;
}

// ---- link layer -> IP -------------------------------------------------------

// Pull { version, dst } (dst = address bytes) out of one captured frame, or
// null when the frame carries no IP packet (ARP, truncated, unknown link type).
export function frameToIp(linkType, frame) {
  let ip = null;
  if (linkType === DLT_EN10MB) ip = ethPayload(frame);
  else if (linkType === DLT_RAW) ip = frame;
  else if (linkType === DLT_LINUX_SLL) ip = sllPayload(frame);
  if (ip === null) return null;
  return ipDst(ip);
}

// Ethernet II: dst(6) src(6) ethertype(2) [802.1Q vlan tag(4)] payload.
function ethPayload(frame) {
  if (frame.length < 14) return null;
  let o = 12;
  let ether = (frame[o] << 8) | frame[o + 1];
  o += 2;
  while (ether === 0x8100 || ether === 0x88a8) {
    // VLAN / QinQ tag: 2 bytes TCI then 2 bytes inner ethertype
    if (o + 4 > frame.length) return null;
    ether = (frame[o + 2] << 8) | frame[o + 3];
    o += 4;
  }
  if (ether !== 0x0800 && ether !== 0x86dd) return null; // not IPv4/IPv6
  return frame.subarray(o);
}

// Linux SLL (cooked): 16-byte header, ethertype at offset 14.
function sllPayload(frame) {
  if (frame.length < 16) return null;
  const ether = (frame[14] << 8) | frame[15];
  if (ether !== 0x0800 && ether !== 0x86dd) return null;
  return frame.subarray(16);
}

// IP header -> { version, dst: Uint8Array }. null when too short / not v4/v6.
function ipDst(ip) {
  if (ip.length < 1) return null;
  const version = ip[0] >> 4;
  if (version === 4) {
    if (ip.length < 20) return null;
    return { version: 4, dst: ip.subarray(16, 20) };
  }
  if (version === 6) {
    if (ip.length < 40) return null;
    return { version: 6, dst: ip.subarray(24, 40) };
  }
  return null;
}

// ---- address classification -------------------------------------------------

// The classes. "egress" is the only one that fails the gate.
export const LOCAL = "local"; // loopback
export const LINKLOCAL = "link-local";
export const MULTICAST = "multicast";
export const DECLARED = "declared-peer";
export const EGRESS = "egress";

export function isLoopback(version, a) {
  if (version === 4) return a[0] === 127;
  return isV6(a, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // ::1
}
export function isLinkLocal(version, a) {
  if (version === 4) return a[0] === 169 && a[1] === 254; // 169.254/16
  return a[0] === 0xfe && (a[1] & 0xc0) === 0x80; // fe80::/10
}
export function isMulticast(version, a) {
  if (version === 4) return a[0] >= 224 && a[0] <= 239; // 224.0.0.0/4
  return a[0] === 0xff; // ff00::/8
}
export function isUnspecified(version, a) {
  if (version === 4) return a[0] === 0 && a[1] === 0 && a[2] === 0 && a[3] === 0;
  return isV6(a, new Array(16).fill(0)); // ::
}

// A declared peer is given as a CIDR in the manifest (v4 "10.9.9.0/24" or an
// exact v6 address). Returns true when `a` falls inside `cidr`.
export function inCidr(version, a, cidr) {
  const slash = cidr.indexOf("/");
  const head = slash === -1 ? cidr : cidr.slice(0, slash);
  const bits = slash === -1 ? (version === 4 ? 32 : 128) : parseInt(cidr.slice(slash + 1), 10);
  const net = version === 4 ? v4Bytes(head) : v6Bytes(head);
  if (net === null) return false; // malformed CIDR, or wrong family for this head
  let remaining = bits;
  for (let i = 0; i < a.length; i++) {
    if (remaining <= 0) break;
    const take = remaining >= 8 ? 8 : remaining;
    const mask = take === 8 ? 0xff : (0xff << (8 - take)) & 0xff;
    if ((a[i] & mask) !== (net[i] & mask)) return false;
    remaining -= 8;
  }
  return true;
}

// Classify one observed destination against the declared-peer allowlist.
export function classify(version, dst, declaredPeers) {
  if (isLoopback(version, dst)) return LOCAL;
  if (isUnspecified(version, dst)) return LOCAL;
  if (isLinkLocal(version, dst)) return LINKLOCAL;
  if (isMulticast(version, dst)) return MULTICAST;
  for (const cidr of declaredPeers) {
    if (inCidr(version, dst, cidr)) return DECLARED;
  }
  return EGRESS;
}

// ---- the verdict ------------------------------------------------------------

// Render the re-runnable verdict from captured bytes + a manifest.
// Deterministic: the same (pcap, manifest) yields byte-identical output. No
// timestamps, no ordering surprises — observed destinations are returned sorted
// and de-duplicated so the result is a pure function of what was seen.
export function witnessEgress(pcapBuf, manifest = {}) {
  const declared = Array.isArray(manifest.declaredPeers) ? manifest.declaredPeers : [];
  const records = parsePcap(pcapBuf);
  const seen = new Map(); // key -> { dst, version, class, count }
  let framesWithIp = 0;
  for (const rec of records) {
    const info = frameToIp(rec.linkType, rec.frame);
    if (info === null) continue; // non-IP frame (ARP, etc.) — nothing to route out
    framesWithIp++;
    const text = ipToString(info.version, info.dst);
    const cls = classify(info.version, info.dst, declared);
    const key = info.version + "|" + text;
    const prev = seen.get(key);
    if (prev) prev.count++;
    else seen.set(key, { dst: text, version: info.version, class: cls, count: 1 });
  }
  const observed = [...seen.values()].sort((x, y) =>
    x.dst < y.dst ? -1 : x.dst > y.dst ? 1 : x.version - y.version
  );
  const egressFlows = observed.filter((o) => o.class === EGRESS);
  return {
    verdict: egressFlows.length === 0 ? "CLEAN" : "CAUGHT",
    egressCount: egressFlows.length,
    egressFlows,
    observed,
    totalFrames: records.length,
    ipFrames: framesWithIp,
    declaredPeers: declared,
  };
}

// ---- the re-runnable report -------------------------------------------------

export const THREAT_MODEL =
  "Egress is observed at the host / network-namespace boundary over the capture " +
  "window. A kernel- or firmware-level implant BELOW this capture point can move " +
  "bytes this never sees — so this is 'observed egress zero under a stated threat " +
  "model', not 'proof of a negative'. L3 (OS) and L2 (firmware) are the next layers " +
  "down: adopt-and-prove, not claimed here.";

// Assemble the re-runnable report from captured bytes + manifest + provenance.
// Pure and deterministic: identical (pcapBuf, manifest, meta) -> identical object.
// `meta` carries provenance computed by the caller (hashes are I/O): pcapSha256,
// pcapBytes, workload (its name + source sha256), capturedBy, window.
export function buildReport(pcapBuf, manifest = {}, meta = {}) {
  const w = witnessEgress(pcapBuf, manifest);
  return {
    tool: "airgap-prover",
    verdict: w.verdict,
    egressCount: w.egressCount,
    threatModel: THREAT_MODEL,
    workload: meta.workload || null,
    capturedBy: meta.capturedBy || null,
    pcapSha256: meta.pcapSha256 || null,
    pcapBytes: typeof meta.pcapBytes === "number" ? meta.pcapBytes : null,
    declaredPeers: w.declaredPeers,
    totalFrames: w.totalFrames,
    ipFrames: w.ipFrames,
    egressFlows: w.egressFlows,
    observed: w.observed,
  };
}

// ---- small deterministic helpers -------------------------------------------

function toU8(buf) {
  if (buf instanceof Uint8Array) return buf;
  if (buf && buf.buffer instanceof ArrayBuffer) return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  if (buf instanceof ArrayBuffer) return new Uint8Array(buf);
  throw new Error("pcap: need bytes");
}
function rd32le(u8, o) {
  return (u8[o] | (u8[o + 1] << 8) | (u8[o + 2] << 16) | (u8[o + 3] << 24)) >>> 0;
}
function rd32be(u8, o) {
  return ((u8[o] << 24) | (u8[o + 1] << 16) | (u8[o + 2] << 8) | u8[o + 3]) >>> 0;
}
function isV6(a, want) {
  for (let i = 0; i < 16; i++) if (a[i] !== want[i]) return false;
  return true;
}
function v4Bytes(s) {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const n = Number(parts[i]);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    out[i] = n;
  }
  return out;
}
function v6Bytes(s) {
  // Supports full and :: compressed forms (enough for declared peers / tests).
  const hasDouble = s.indexOf("::") !== -1;
  let head = s, tail = "";
  if (hasDouble) {
    const bits = s.split("::");
    if (bits.length !== 2) return null;
    head = bits[0];
    tail = bits[1];
  }
  const h = head === "" ? [] : head.split(":");
  const t = tail === "" ? [] : tail.split(":");
  if (!hasDouble && h.length !== 8) return null;
  const mid = 8 - h.length - t.length;
  if (mid < 0) return null;
  const groups = [...h, ...new Array(mid).fill("0"), ...t];
  if (groups.length !== 8) return null;
  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const n = parseInt(groups[i] || "0", 16);
    if (!Number.isFinite(n) || n < 0 || n > 0xffff) return null;
    out[i * 2] = n >> 8;
    out[i * 2 + 1] = n & 0xff;
  }
  return out;
}
export function ipToString(version, a) {
  if (version === 4) return a[0] + "." + a[1] + "." + a[2] + "." + a[3];
  const g = [];
  for (let i = 0; i < 16; i += 2) g.push(((a[i] << 8) | a[i + 1]).toString(16));
  return g.join(":");
}
