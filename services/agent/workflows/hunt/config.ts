import type { BudgetLimits } from "../../contracts/budget.js";
import { SpecError, type Counts, type RunSpec } from "../../core/spec.js";
import { DEFAULT_CHECKPOINTS, type Checkpoints } from "./checkpoints.js";

// The core spec carries domain config as untyped numeric bags, so what a
// threshold means is stated here rather than in a harness the hunt shares.

export interface Verdicts {
  min_corroborating_sources: number;
  gap_lock_threshold: number;
}

// Two systems because one system agreeing with itself is not corroboration;
// three gaps because a hypothesis with that much unseen has not been cleared.
export const DEFAULT_VERDICTS: Verdicts = { min_corroborating_sources: 2, gap_lock_threshold: 3 };

export interface Termination {
  priority_floor: number;
  park_ttl_ms: number;
  hard_max_calls: number;
  hard_max_cost_usd: number;
}

// A frontier score tops out at 16, so five is a novel lead bearing on one active
// hypothesis: below it a lead is backlog rather than a reason to keep spending.
export const DEFAULT_TERMINATION: Termination = {
  priority_floor: 5,
  park_ttl_ms: 604_800_000,
  hard_max_calls: 24,
  hard_max_cost_usd: 10,
};

export interface DigestPolicy {
  evidence_window: number;
  resurface: number;
  rare_pairing_max: number;
  graph_warmup: number;
  contrarian_max: number;
  entity_window: number;
  pivot_candidates: number;
}

export const DEFAULT_DIGEST: DigestPolicy = {
  evidence_window: 25,
  resurface: 3,
  rare_pairing_max: 1,
  graph_warmup: 20,
  contrarian_max: 3,
  entity_window: 15,
  pivot_candidates: 5,
};

// A bag the deployment left out keeps the default, key by key: a config naming
// one threshold should not silently drop the rest.
function over<T extends object>(defaults: T, held: Counts): T {
  const merged = { ...defaults } as Record<string, number>;
  for (const key of Object.keys(defaults)) {
    const value = held[key];
    if (typeof value === "number") merged[key] = value;
  }
  return merged as T;
}

// Checked against the union because verdicts and termination share one bag: a
// threshold of zero locks or proves everything, and a misspelled key is silent.
export function validateThresholds(held: Counts): void {
  const known = { ...DEFAULT_VERDICTS, ...DEFAULT_TERMINATION } as Record<string, number>;
  for (const [key, value] of Object.entries(held)) {
    if (!(key in known)) throw new SpecError(`unknown thresholds key: ${key}`);
    if (!Number.isFinite(value) || value <= 0) throw new SpecError(`thresholds.${key} must be a positive number`);
  }
}

export function verdictsOf(spec: RunSpec): Verdicts {
  return over(DEFAULT_VERDICTS, spec.thresholds);
}

export function terminationOf(spec: RunSpec): Termination {
  return over(DEFAULT_TERMINATION, spec.thresholds);
}

export function digestOf(spec: RunSpec): DigestPolicy {
  return over(DEFAULT_DIGEST, spec.digest);
}

export interface EnrichmentChain {
  id: string;
  on: string;
  tool: string;
  query: string;
}

export interface EnrichmentPolicy {
  max_depth: number;
  max_entities: number;
  chains: EnrichmentChain[];
}

export const DEFAULT_ENRICHMENT: EnrichmentPolicy = { max_depth: 1, max_entities: 8, chains: [] };

// The p.6 hypothesis loop: null seeded at base rate, frontier ranked by
// discrimination, termination on dominance. Per run, so a ledger replays as ranked.
export const DEFAULT_HYPOTHESIS_LOOP = false;

// Typed rather than a bag: a hypothesis is shaped by results and reshaped again,
// so it has to be a first-class record everywhere the workflow touches it.
export interface HuntSpec extends RunSpec {
  hypothesis_loop: boolean;
  hypotheses: string[];
  attack_techniques: string[];
  data_domains: string[];
  enrichment: EnrichmentPolicy;
  checkpoints: Checkpoints;
  termination: Termination;
}

// A ceiling under the budget it caps would clamp every extension to less than
// the hunt already had, so an operator could never buy headroom.
function validateCeilings(termination: Termination, budgets: BudgetLimits): void {
  if (termination.hard_max_calls < budgets.max_calls)
    throw new SpecError(`thresholds.hard_max_calls is below budgets.max_calls (${budgets.max_calls})`);
  if (termination.hard_max_cost_usd < budgets.max_cost_usd)
    throw new SpecError(`thresholds.hard_max_cost_usd is below budgets.max_cost_usd (${budgets.max_cost_usd})`);
}

export function huntSpec(spec: RunSpec): HuntSpec {
  const held = spec.sections;
  validateThresholds(spec.thresholds);
  validateCeilings(terminationOf(spec), spec.budgets);
  return {
    ...spec,
    hypothesis_loop: held["hypothesis_loop"] === true,
    hypotheses: Array.isArray(held["hypotheses"]) ? (held["hypotheses"] as string[]) : [],
    attack_techniques: Array.isArray(held["attack_techniques"]) ? (held["attack_techniques"] as string[]) : [],
    data_domains: Array.isArray(held["data_domains"]) ? (held["data_domains"] as string[]) : [],
    enrichment: { ...DEFAULT_ENRICHMENT, ...(held["enrichment"] as object | undefined) },
    checkpoints: { ...DEFAULT_CHECKPOINTS, ...(held["checkpoints"] as object | undefined) },
    termination: terminationOf(spec),
  };
}
