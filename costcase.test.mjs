// costcase.test.mjs — the buyer cost case against its falsifiable boundaries.
// Written to kill witness mutants: each comparison / operator has a test that
// flips the result when the operator is flipped.
import { test } from "node:test";
import assert from "node:assert/strict";
import { costCase, num, round2, DEFAULTS } from "./costcase.mjs";

// ---- num: clamp to finite, non-negative, else default ----------------------
test("num: accepts a non-negative number, parses strings", () => {
  assert.equal(num(5, 1), 5);
  assert.equal(num("7.5", 1), 7.5);
  assert.equal(num(0, 1), 0); // zero is valid, not falsy-replaced
});
test("num: rejects negative, NaN, undefined -> default (< 0 boundary)", () => {
  assert.equal(num(-1, 9), 9);
  assert.equal(num(-0.0001, 9), 9);
  assert.equal(num("abc", 9), 9);
  assert.equal(num(undefined, 9), 9);
  assert.equal(num(Infinity, 9), 9);
});

// ---- round2: deterministic pennies -----------------------------------------
test("round2 rounds to two places, half up", () => {
  assert.equal(round2(1.005), 1.01);
  assert.equal(round2(2.344), 2.34);
  assert.equal(round2(100), 100);
});

// ---- costCase: the arithmetic holds ----------------------------------------
test("costCase with defaults: manual > proven, saving positive, pct in (0,100)", () => {
  const r = costCase();
  // defaults: 10 workloads x 4 cycles = 40 attestations; manual 6h @ £65 = 15600
  assert.equal(r.attestations, 40);
  assert.equal(r.manualAnnual, 40 * 6 * 65);
  // proven: review 0.25h x 40 @ £65 + (16h x £65)/3
  assert.equal(r.provenAnnual, round2(40 * 0.25 * 65 + (16 * 65) / 3));
  assert.ok(r.savingAnnual > 0, "saving is positive at defaults");
  assert.ok(r.savingPct > 0 && r.savingPct < 100, "pct strictly within (0,100)");
  assert.equal(r.savingAnnual, round2(r.manualAnnual - r.provenAnnual));
});
test("costCase: saving = manual - proven exactly; hoursRemoved = manual - review", () => {
  const r = costCase({ workloads: 5, cyclesPerYear: 2, manualHours: 4, rate: 50, setupHours: 0, reviewHours: 0 });
  assert.equal(r.attestations, 10);
  assert.equal(r.manualAnnual, 10 * 4 * 50); // 2000
  assert.equal(r.provenAnnual, 0); // no review, no setup
  assert.equal(r.savingAnnual, 2000);
  assert.equal(r.savingPct, 100); // proven 0 -> 100% saved
  assert.equal(r.hoursRemoved, 10 * 4); // 40h
});
test("costCase: manualAnnual 0 -> savingPct 0, never divide-by-zero (> 0 guard)", () => {
  const r = costCase({ workloads: 0, setupHours: 0, reviewHours: 0 });
  assert.equal(r.manualAnnual, 0);
  assert.equal(r.savingPct, 0); // the manualAnnual>0 guard holds
});
test("costCase: fteRemoved divides the removed hours by the 1600h floor", () => {
  const r = costCase({ workloads: 10, cyclesPerYear: 4, manualHours: 40, reviewHours: 0, setupHours: 0 });
  // 40 attestations x 40h = 1600h removed -> 1.0 FTE
  assert.equal(r.hoursRemoved, 1600);
  assert.equal(r.fteRemoved, 1);
});
test("costCase: bad inputs fall back to defaults (does not throw on garbage)", () => {
  const r = costCase({ workloads: -3, rate: "oops", cyclesPerYear: NaN });
  assert.equal(r.inputs.workloads, DEFAULTS.workloads);
  assert.equal(r.inputs.rate, DEFAULTS.rate);
  assert.equal(r.inputs.cyclesPerYear, DEFAULTS.cyclesPerYear);
});
test("costCase output is deterministic (pure) for identical inputs", () => {
  const a = costCase({ workloads: 7, rate: 72.5 });
  const b = costCase({ workloads: 7, rate: 72.5 });
  assert.deepEqual(a, b);
});
