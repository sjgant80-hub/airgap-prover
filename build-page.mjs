#!/usr/bin/env node
// build-page.mjs — inline the REAL kernel + the committed fixtures into one
// single-file index.html. The decision logic on the page is egress.mjs verbatim
// (export keywords stripped), so the gated code IS the live code. Deterministic:
// CI regenerates and diffs, so the page can never drift from the kernel.

import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));

// 1) the kernel, module scaffolding stripped (no imports to remove — it's pure)
let kernel = readFileSync(join(HERE, "egress.mjs"), "utf8");
kernel = kernel.replace(/^#!.*\r?\n/, "").replace(/\bexport\s+/g, "");

// 2) the committed fixtures, base64-encoded, + expected.json + the manifest
const fxDir = join(HERE, "fixtures");
const expected = JSON.parse(readFileSync(join(fxDir, "expected.json"), "utf8"));
const fixtures = {};
for (const name of readdirSync(fxDir)) {
  if (!name.endsWith(".pcap")) continue;
  fixtures[name] = readFileSync(join(fxDir, name)).toString("base64");
}

// 3) inject into the template at raw-text markers (no string escaping of code)
let html = readFileSync(join(HERE, "page.template.html"), "utf8");
html = html
  .replace("/*KERNEL*/", kernel)
  .replace("/*FIXTURES*/", JSON.stringify(fixtures))
  .replace("/*EXPECTED*/", JSON.stringify(expected));

writeFileSync(join(HERE, "index.html"), html);
console.log(`built index.html (kernel ${kernel.length}B, ${Object.keys(fixtures).length} fixtures inlined)`);
