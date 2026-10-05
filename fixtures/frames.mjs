// fixtures/frames.mjs — pure, deterministic pcap/frame builders (no side effects).
// Shared by fixtures/make.mjs and egress.test.mjs.

const DST_MAC = [0x02, 0, 0, 0, 0, 0x02];
const SRC_MAC = [0x02, 0, 0, 0, 0, 0x01];

export function v4(s) {
  return s.split(".").map(Number);
}
export function v6(s) {
  const out = [];
  for (const h of s.split(":")) {
    const n = parseInt(h || "0", 16);
    out.push(n >> 8, n & 0xff);
  }
  return out;
}
export function ipv4Frame(dst) {
  const d = v4(dst);
  const ip = [0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 9, ...d];
  return [...DST_MAC, ...SRC_MAC, 0x08, 0x00, ...ip];
}
export function ipv6Frame(dst) {
  const d = v6(dst);
  const src = v6("fd00:0:0:0:0:0:0:9");
  const ip = [0x60, 0, 0, 0, 0, 0, 6, 64, ...src, ...d];
  return [...DST_MAC, ...SRC_MAC, 0x86, 0xdd, ...ip];
}
// ARP frame (ethertype 0x0806) — a non-IP frame the witness must ignore.
export function arpFrame() {
  return [...DST_MAC, ...SRC_MAC, 0x08, 0x06, ...new Array(28).fill(0)];
}
// 802.1Q VLAN-tagged IPv4 frame (tag 0x8100) to exercise the tag-unwrap loop.
export function vlanIpv4Frame(dst) {
  const d = v4(dst);
  const ip = [0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 9, ...d];
  return [...DST_MAC, ...SRC_MAC, 0x81, 0x00, 0x00, 0x64, 0x08, 0x00, ...ip];
}
// Raw-IP record payload (no Ethernet) for DLT_RAW captures.
export function rawIpv4(dst) {
  const d = v4(dst);
  return [0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 9, ...d];
}
// Linux SLL ("cooked", DLT 113) IPv4/IPv6 frames: 16-byte header, ethertype at
// offset 14, then the IP packet.
export function sllIpv4Frame(dst) {
  const d = v4(dst);
  const ip = [0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 9, ...d];
  return [0, 0, 0, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x00, ...ip];
}
export function sllIpv6Frame(dst) {
  const d = v6(dst);
  const src = v6("fd00:0:0:0:0:0:0:9");
  const ip = [0x60, 0, 0, 0, 0, 0, 6, 64, ...src, ...d];
  return [0, 0, 0, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0x86, 0xdd, ...ip];
}
// A large IPv4 Ethernet frame (padded to `total` bytes) — forces multi-byte
// pcap length fields so a corrupted little-endian field reader is caught.
export function bigIpv4Frame(dst, total = 300) {
  const f = ipv4Frame(dst);
  while (f.length < total) f.push(0);
  return f;
}
// A raw record-header blob with a given incl_len but no body (zero-body record).
export function zeroBodyRecord() {
  // 16-byte record header, incl_len = 0
  return { header: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] };
}

function push32le(arr, n) {
  arr.push(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff);
}
function push32be(arr, n) {
  arr.push((n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
}

// Build a little-endian pcap buffer from a list of frames (byte arrays).
export function pcap(frames, linkType = 1) {
  const bytes = [];
  push32le(bytes, 0xa1b2c3d4);
  bytes.push(2, 0, 4, 0);
  push32le(bytes, 0);
  push32le(bytes, 0);
  push32le(bytes, 65535);
  push32le(bytes, linkType);
  let ts = 1700000000;
  for (const f of frames) {
    push32le(bytes, ts++);
    push32le(bytes, 0);
    push32le(bytes, f.length);
    push32le(bytes, f.length);
    for (const b of f) bytes.push(b & 0xff);
  }
  return Buffer.from(bytes);
}

// Build a BIG-endian pcap buffer (same frames) to prove endianness handling.
export function pcapBE(frames, linkType = 1) {
  const bytes = [];
  push32be(bytes, 0xa1b2c3d4);
  bytes.push(0, 2, 0, 4);
  push32be(bytes, 0);
  push32be(bytes, 0);
  push32be(bytes, 65535);
  push32be(bytes, linkType);
  let ts = 1700000000;
  for (const f of frames) {
    push32be(bytes, ts++);
    push32be(bytes, 0);
    push32be(bytes, f.length);
    push32be(bytes, f.length);
    for (const b of f) bytes.push(b & 0xff);
  }
  return Buffer.from(bytes);
}
