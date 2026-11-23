// page-script.test.mjs — the built live page's own inline scripts must parse.
// A single stray bracket in index.html's module script stops every section on
// the page while every other test stays green (it has happened elsewhere in the
// estate). Node checks each inline script's syntax here, without running it.
// Also asserts the air-gap markers were resolved — an unreplaced /*MARKER*/ is a
// syntax error the --check would catch, but we name it so the failure is legible.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";

const HERE = dirname(fileURLToPath(import.meta.url));

test("every inline <script> on the built page parses", () => {
  const html = readFileSync(join(HERE, "index.html"), "utf8");
  const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)([^>]*)>([\s\S]*?)<\/script>/g)]
    .filter((m) => !/type="application\/(ld\+)?json"/.test(m[1]));
  assert.ok(scripts.length >= 1, "the page has at least one inline script");
  const dir = mkdtempSync(join(tmpdir(), "agp-page-"));
  try {
    scripts.forEach((m, i) => {
      const file = join(dir, "script-" + i + (/type="module"/.test(m[1]) ? ".mjs" : ".js"));
      writeFileSync(file, m[2]);
      const r = spawnSync(process.execPath, ["--check", file], { encoding: "utf8" });
      assert.equal(r.status, 0, "script " + i + " does not parse: " + (r.stderr || "").split("\n").slice(0, 5).join(" "));
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("no build-page marker was left unresolved in index.html", () => {
  const html = readFileSync(join(HERE, "index.html"), "utf8");
  for (const marker of ["/*KERNEL*/", "/*COSTCASE_KERNEL*/", "/*FIXTURES*/", "/*EXPECTED*/", "/*LIVE_FIXTURES*/", "/*LIVE_EXPECTED*/", "/*AIRGAP_FIXTURES*/", "/*AIRGAP_EXPECTED*/"]) {
    assert.ok(!html.includes(marker), "unresolved marker in index.html: " + marker);
  }
});

test("the built page carries the vantage ladder and air-gap set", () => {
  const html = readFileSync(join(HERE, "index.html"), "utf8");
  for (const needle of ["external-tap", "physical-airgap", "airgapcards", "AIRGAP_FIXTURES", "Faraday", "the business case", "costCase(", "AI Native Solutions", "board case"]) {
    assert.ok(html.includes(needle), "built page is missing: " + needle);
  }
});
