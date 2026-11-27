// claims.test.mjs — claims.json is current, and every claim in it can FAIL on a tampered record.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { load, evaluate, json, REGISTERED } from './scripts/make-claims.mjs';
import { witnessEgress } from './egress.mjs';

const ROOT = dirname(fileURLToPath(import.meta.url));
const by = (v) => Object.fromEntries(v.map((c) => [c.id, c]));
const fresh = () => load(ROOT);
const set = (F, d) => F.sets.find((s) => s.dir === d);

test('claims.json is exactly what the committed captures force (run: node scripts/make-claims.mjs)', () => {
  assert.equal(readFileSync(join(ROOT, 'claims.json'), 'utf8'), json(), 'claims.json is stale — regenerate it with: node scripts/make-claims.mjs');
});

test('on the committed captures: A1-A4 pass, A5 is pending (not measured, never a pass)', () => {
  const v = by(evaluate(fresh()));
  for (const id of ['A1', 'A2', 'A3', 'A4']) assert.equal(v[id].pass, true, `${id}: ${v[id].result}`);
  assert.equal(v.A5.pass, null);
});

test('each claim says how it was registered, and only A1-A3 say pre-registered', () => {
  for (const id of ['A1', 'A2', 'A3']) assert.match(REGISTERED[id], /^pre-registered/);
  for (const id of ['A4', 'A5']) assert.doesNotMatch(REGISTERED[id], /^pre-registered/);
});

test('A1 fails if the offline capture shows egress', () => {
  const k = (b, m) => { const r = witnessEgress(b, m); return b === set(F1, 'fixtures/live').pcaps['offline.pcap'] ? { ...r, verdict: 'CAUGHT', egressCount: 1 } : r; };
  const F1 = fresh();
  assert.equal(by(evaluate(F1, k)).A1.pass, false);
});

test('A2 fails if phone-home is flagged somewhere other than the address it called', () => {
  const F = fresh(); const pb = set(F, 'fixtures/live').pcaps['phonehome.pcap'];
  const k = (b, m) => { const r = witnessEgress(b, m); return b === pb ? { ...r, egressFlows: [{ dst: '1.1.1.1', class: 'egress' }] } : r; };
  assert.equal(by(evaluate(F, k)).A2.pass, false);
});

test('A3 fails if a pinned verdict drifts', () => {
  const F = fresh(); const s = set(F, 'fixtures');
  const name = Object.keys(s.expected).find((n) => !n.startsWith('__'));
  s.expected = { ...s.expected, [name]: { ...s.expected[name], egressCount: 99 } };
  assert.equal(by(evaluate(F)).A3.pass, false);
});

test('A3 fails if a capture is committed with no pinned verdict', () => {
  const F = fresh(); const s = set(F, 'fixtures');
  s.pcaps = { ...s.pcaps, 'unpinned.pcap': Buffer.alloc(0) };
  assert.equal(by(evaluate(F)).A3.pass, false);
});

test('A4 fails if air-gap mode catches nothing more than connected mode', () => {
  const F = fresh(); const lb = set(F, 'fixtures/airgap').pcaps['airgap-leak.pcap'];
  const k = (b, m) => { const r = witnessEgress(b, m); return b === lb ? { ...r, verdict: 'CAUGHT', egressCount: 1 } : r; };
  assert.equal(by(evaluate(F, k)).A4.pass, false);
});

test('A5 turns to a pass once a capture from a vantage below the host is committed', () => {
  const F = fresh(); set(F, 'fixtures/live').manifest = { ...set(F, 'fixtures/live').manifest, vantage: 'external-tap' };
  assert.equal(by(evaluate(F)).A5.pass, true);
});
