// make-claims.mjs — airgap-prover's claims, each verdict COMPUTED by running the egress kernel on the
// committed captures (the same pure call rerun.mjs and the live page make). Writes claims.json; `--check`
// fails if claims.json is not what the captures force, so it can never drift from the record.
//
// HOW EACH CLAIM WAS REGISTERED (stated per claim, because it differs):
//   A1-A3  PRE-REGISTERED: predictions committed in 50a91b0 (2026-10-05 18:53), before the measured run
//          recorded in 85b8fc7 (19:00). SEAL.md holds the prereg text.
//   A4     PROVEN, NOT PRE-REGISTERED: the air-gap fixtures and their expected verdicts were committed in the
//          same commit as the code (316d9fe, 2026-11-23); no prereg commit preceded them.
//   A5     STATED UP FRONT AS NOT MEASURED (4842821): pending until a live capture from a vantage below the
//          host is committed.
import { readFileSync, readdirSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { witnessEgress } from '../egress.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SETS = ['fixtures', 'fixtures/airgap', 'fixtures/live'];
const BELOW_HOST = ['external-tap', 'physical-airgap'];

export const NAMES = {
  A1: 'The offline workload shows zero egress',
  A2: 'The phone-home control is caught, at the address it called',
  A3: 'Every pinned capture re-derives byte for byte',
  A4: 'Air-gap mode catches what connected mode admits',
  A5: 'A live capture from a vantage below the host',
};
export const REGISTERED = {
  A1: 'pre-registered (50a91b0, before the measured run 85b8fc7)',
  A2: 'pre-registered (50a91b0, before the measured run 85b8fc7)',
  A3: 'pre-registered (50a91b0, before the measured run 85b8fc7)',
  A4: 'proven by committed fixtures (316d9fe) — not separately pre-registered',
  A5: 'stated up front as not measured (4842821)',
};

// load(root) → { sets: [{ dir, manifest, expected, pcaps: { name: Buffer } }] }
export function load(root = ROOT) {
  return { sets: SETS.filter((d) => existsSync(join(root, d, 'expected.json'))).map((d) => {
    const expected = JSON.parse(readFileSync(join(root, d, 'expected.json'), 'utf8'));
    const pcaps = Object.fromEntries(readdirSync(join(root, d)).filter((f) => f.endsWith('.pcap')).map((f) => [f, readFileSync(join(root, d, f))]));
    return { dir: d, manifest: expected.__manifest || {}, expected, pcaps };
  }) };
}

// evaluate(F, kernel) → [{ id, name, registered, pass, result }]
export function evaluate(F, kernel = witnessEgress) {
  const set = (d) => (F.sets || []).find((s) => s.dir === d);
  const run = (s, name, manifest) => (s && s.pcaps[name] ? kernel(s.pcaps[name], manifest ?? s.manifest) : null);
  const row = (id, pass, result) => ({ id, name: NAMES[id], registered: REGISTERED[id], pass, result });
  const out = [];

  const live = set('fixtures/live');
  const off = run(live, 'offline.pcap');
  out.push(!off ? row('A1', null, 'pending: no committed offline capture')
    : row('A1', off.verdict === 'CLEAN' && off.egressCount === 0, `the committed offline capture: ${off.verdict}, egress ${off.egressCount}, over ${off.totalFrames} frames`));

  const ph = run(live, 'phonehome.pcap');
  const hit = ph && Array.isArray(ph.egressFlows) && ph.egressFlows.some((f) => f.dst === '8.8.8.8');
  out.push(!ph ? row('A2', null, 'pending: no committed phone-home capture')
    : row('A2', ph.verdict === 'CAUGHT' && hit === true, `the committed phone-home capture: ${ph.verdict}, egress ${ph.egressCount}${hit ? ', flagged at 8.8.8.8' : ', 8.8.8.8 not flagged'}`));

  let checked = 0, drift = 0, unpinned = 0;
  for (const s of F.sets || []) {
    for (const name of Object.keys(s.expected)) {
      if (name.startsWith('__')) continue;
      checked++;
      const got = run(s, name);
      if (!got || JSON.stringify(got) !== JSON.stringify(s.expected[name])) drift++;
    }
    for (const p of Object.keys(s.pcaps)) if (!(p in s.expected)) unpinned++;
  }
  out.push(row('A3', checked > 0 && drift === 0 && unpinned === 0, `${checked - drift} of ${checked} pinned captures re-derive identically; ${unpinned} capture${unpinned === 1 ? '' : 's'} with no pinned verdict`));

  const ag = set('fixtures/airgap');
  const silent = run(ag, 'airgap-silent.pcap');
  const leakAir = run(ag, 'airgap-leak.pcap');
  const { mode, ...connected } = (ag && ag.manifest) || {};
  const leakConn = run(ag, 'airgap-leak.pcap', connected);
  out.push(!silent || !leakAir || !leakConn ? row('A4', null, 'pending: the air-gap fixtures are missing')
    : row('A4', mode === 'airgap' && silent.verdict === 'CLEAN' && leakAir.verdict === 'CAUGHT' && leakAir.egressCount > leakConn.egressCount,
      `silent capture: ${silent.verdict}; the leak capture shows egress ${leakAir.egressCount} in air-gap mode against ${leakConn.egressCount} in connected mode`));

  const below = (F.sets || []).filter((s) => BELOW_HOST.includes(s.manifest.vantage));
  out.push(below.length === 0 ? row('A5', null, 'pending: the kernel supports external-tap and physical-airgap and fixtures prove them, but no live capture from those vantages is committed (a two-machine procedure; documented on the page)')
    : row('A5', true, `${below.length} committed capture set(s) from a vantage below the host: ${below.map((s) => s.manifest.vantage).join(', ')}`));

  return out;
}

export function build() {
  const claims = evaluate(load());
  return { build: 'airgap-prover', passed: claims.filter((c) => c.pass === true).length, total: claims.length,
    source: 'generated by scripts/make-claims.mjs by running egress.mjs on the committed captures (fixtures/, fixtures/airgap/, fixtures/live/)',
    claims };
}
export const json = () => JSON.stringify(build(), null, 2) + '\n';

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const j = json(), b = JSON.parse(j);
  if (process.argv.includes('--check')) {
    let cur = ''; try { cur = readFileSync(join(ROOT, 'claims.json'), 'utf8'); } catch { /* missing */ }
    if (cur !== j) { console.error('claims.json is stale — run: node scripts/make-claims.mjs'); process.exit(1); }
    console.log('claims.json is current:', b.passed + '/' + b.total);
  } else { writeFileSync(join(ROOT, 'claims.json'), j); console.log('wrote claims.json', b.passed + '/' + b.total); for (const c of b.claims) console.log(' ', c.id, c.pass === true ? 'PASS' : c.pass === false ? 'FAIL' : 'pending', '—', c.result); }
}
