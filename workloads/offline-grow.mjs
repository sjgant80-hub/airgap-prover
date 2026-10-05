#!/usr/bin/env node
// offline-grow.mjs — a REPRESENTATIVE OFFLINE WORKLOAD.
//
// Deterministic local compute that stands in for the estate's genuinely offline
// jobs (a seed-library grow, a spore germination, a pattern-organs run): it does
// real work — grows a prime-spine sequence and folds it into a digest — and
// touches NOTHING on the network. No fetch, no sockets, no DNS. When this runs
// inside the locked namespace, the host-side capture must show ZERO egress.

function isPrime(n) {
  if (n < 2) return false;
  for (let d = 2; d * d <= n; d++) if (n % d === 0) return false;
  return true;
}

// Grow a prime spine and fold it into a rolling digest — pure CPU, no I/O.
let n = 1;
let digest = 2166136261 >>> 0; // FNV-1a seed
const spine = [];
for (let i = 0; i < 2000; i++) {
  do {
    n++;
  } while (!isPrime(n));
  spine.push(n);
  digest = (digest ^ n) >>> 0;
  digest = Math.imul(digest, 16777619) >>> 0;
}

console.log(`[offline-grow] grew ${spine.length} primes, last=${spine[spine.length - 1]}`);
console.log(`[offline-grow] fold digest=0x${digest.toString(16)}`);
console.log("[offline-grow] done — made no network calls.");
