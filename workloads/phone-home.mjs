#!/usr/bin/env node
// phone-home.mjs — THE POSITIVE CONTROL.
//
// A workload that DOES try to leave. It opens a TCP connection to a public
// address (8.8.8.8:443). Run inside the locked namespace, the SYN is emitted
// onto the veth where the host-side capture sees it — but the host does not
// forward or NAT, so the packet dies at the boundary and never reaches Google.
// The point is only to prove the prover CATCHES the attempt (0 false-pass):
// if airgap-prover reported CLEAN for this run, the prover would be worthless.

import net from "node:net";

const HOST = "8.8.8.8";
const PORT = 443;

console.log(`[phone-home] attempting outbound TCP to ${HOST}:${PORT} ...`);

const sock = net.connect({ host: HOST, port: PORT });
sock.setTimeout(3000);
sock.on("connect", () => {
  console.log("[phone-home] connected (unexpected in a sealed run) — closing");
  sock.destroy();
});
sock.on("timeout", () => {
  console.log("[phone-home] timed out — but the SYN was already emitted onto the wire");
  sock.destroy();
});
sock.on("error", (e) => {
  console.log(`[phone-home] socket error (${e.code}) — the SYN was still emitted; the capture has it`);
});
sock.on("close", () => {
  console.log("[phone-home] done — the attempt is what the prover must catch.");
  process.exit(0);
});
