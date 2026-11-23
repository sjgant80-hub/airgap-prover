// costcase.mjs — the BUYER's cost case, computed, not typed (zero-dep, Node + browser).
//
// airgap-prover does not sell seats. Its saving is the audit-evidence LABOUR it
// takes off your people: today a security engineer captures traffic, reviews it,
// and writes an "it made no outbound calls" attestation by hand, per workload,
// every audit cycle. airgap-prover emits a re-runnable receipt from CI instead.
//
// HONEST by construction: every number below is the BUYER's own, entered by the
// buyer. The DEFAULTS are illustrative floor figures to be replaced with theirs —
// they are NOT claims about any real organisation, and nothing here is a price
// for airgap-prover (it is MIT — no licence fee). The figure is COMPUTED from the
// inputs, never written as a conclusion.

export const DEFAULTS = {
  workloads: 10, // AI / compute workloads that need egress assurance
  cyclesPerYear: 4, // audit / re-attestation cycles per year
  manualHours: 6, // engineer-hours to capture + review + attest ONE workload, per cycle
  rate: 65, // loaded £/hr for the engineer doing it (illustrative floor — set to yours)
  setupHours: 16, // one-time hours to wire airgap-prover into CI (amortised over 3 years)
  reviewHours: 0.25, // engineer-hours to glance at ONE auto-generated receipt, per cycle
};

// Clamp an input to a finite, non-negative number, falling back to a default.
export function num(v, dflt) {
  const n = typeof v === "number" ? v : parseFloat(v);
  if (!Number.isFinite(n) || n < 0) return dflt;
  return n;
}

// Round to pennies for money, deterministically (no float drift in the output).
export function round2(n) {
  return Math.round((n + Number.EPSILON) * 100) / 100;
}

// The cost case. Pure and deterministic: identical inputs -> identical object.
export function costCase(input = {}) {
  const workloads = num(input.workloads, DEFAULTS.workloads);
  const cyclesPerYear = num(input.cyclesPerYear, DEFAULTS.cyclesPerYear);
  const manualHours = num(input.manualHours, DEFAULTS.manualHours);
  const rate = num(input.rate, DEFAULTS.rate);
  const setupHours = num(input.setupHours, DEFAULTS.setupHours);
  const reviewHours = num(input.reviewHours, DEFAULTS.reviewHours);

  const attestations = workloads * cyclesPerYear; // evidence items produced per year

  // Manual today: an engineer does every attestation by hand, every cycle.
  const manualHoursYear = attestations * manualHours;
  const manualAnnual = manualHoursYear * rate;

  // With airgap-prover: CI produces the receipt; the engineer only reviews it.
  // Plus a one-time integration, amortised over three years.
  const reviewHoursYear = attestations * reviewHours;
  const setupAnnualised = (setupHours * rate) / 3;
  const provenAnnual = reviewHoursYear * rate + setupAnnualised;

  const savingAnnual = manualAnnual - provenAnnual;
  const savingPct = manualAnnual > 0 ? (savingAnnual / manualAnnual) * 100 : 0;

  // The audit labour taken off people, in full-time-equivalents (1 FTE ~ 1600 h/yr
  // of chargeable audit work — a floor, deliberately conservative).
  const hoursRemoved = manualHoursYear - reviewHoursYear;
  const fteRemoved = hoursRemoved / 1600;

  return {
    inputs: { workloads, cyclesPerYear, manualHours, rate, setupHours, reviewHours },
    attestations,
    manualAnnual: round2(manualAnnual),
    provenAnnual: round2(provenAnnual),
    savingAnnual: round2(savingAnnual),
    savingPct: Math.round(savingPct * 10) / 10,
    hoursRemoved: round2(hoursRemoved),
    fteRemoved: Math.round(fteRemoved * 100) / 100,
    basis:
      "Computed from the inputs above — your own figures. Defaults are an illustrative floor, " +
      "not a claim about your organisation. airgap-prover is MIT: no licence fee, no per-seat cost.",
  };
}
