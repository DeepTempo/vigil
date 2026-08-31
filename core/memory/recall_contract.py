"""The recall contract (#729), Python's half.

The two contracts between this side and the harness, pinned before either side
builds against them: what a read of episodic memory returns, and the signature
of the tool that performs one. A mismatch fails as "no history" — the same
shape as every other silent failure in this area — so it is agreed before code
exists rather than discovered after.

The TypeScript half is ``services/agent/contracts/memory.ts``.
``tests/unit/_ratchets/test_recall_contract_agrees.py`` fails when the two
drift, which is what makes this an agreement rather than two documents.

There is one shape, carried two ways. The run-start read journals it verbatim
as the recall event payload; a mid-run :data:`RECALL_TOOL` call carries the same
mapping as the single row of a ``ToolResult``. Not two shapes that agree — a
parallel payload is a second contract, and the second one drifts.

Nothing calls this yet. ``distil`` (#731) writes the rows, #732 lands the tool,
and the harness lands the event. Arriving first is the point: three slices join
to one declaration instead of three guesses.
"""

from __future__ import annotations

from typing import Dict, Mapping, Tuple

RECALL_TOOL = "recall_entity"

# What the arch asks for, not what this deployment calls it: a ToolSpec binds the
# capability to the tool id via `provides`. A capability nothing provides is
# dropped rather than fatal, so a role may ask for recall where there is no
# memory yet.
RECALL_CAPABILITY = "entity_recall"

# Which caller gets which tool, empties included: a role granted nothing is a
# decision, and reads as an oversight when it is left out.
#
# Keyed by the role names `services/agent/arch/threathunt.yaml` actually declares,
# not by a class called "worker" that appears in no file. The arch nests the three
# under `roles.workers`, and a grant is written on each.
#
# Workers get exact lookups. The lead does not — it never queries, it reads a
# digest — and narrative search, the lead's alone, ships no tool here. The critic
# already holds nothing.
#
# The run-start read appears nowhere below: it is not a tool call, so it needs no
# grant. Which is also why only it needs an event kind of its own, while a
# mid-run call is journaled as an ordinary dispatch.
RECALL_GRANTS: Mapping[str, Tuple[str, ...]] = {
    "lead": (),
    "critic": (),
    "threat_hunter": (RECALL_CAPABILITY,),
    "network_analyst": (RECALL_CAPABILITY,),
    "threat_intel": (RECALL_CAPABILITY,),
}

# The arguments the tool accepts. `entity_keys` is the contract; a singular
# `entity_key` is wrapped, because a model given a list parameter will sometimes
# send one string.
#
# The handler takes an args mapping and not these as keyword parameters:
# `tools_router._bounded` injects `limit` into every backend call from the
# harness's bounds, and a handler with an explicit signature would answer
# `invalid_args` to every recall. That bound is also not honoured — the caps
# here are memory's own and are reported back in `ranking`, and letting a
# per-tool row ceiling replace them would make what a run remembered depend on
# a number set for a different reason.
RECALL_ARGS: Tuple[str, ...] = (
    "entity_keys",
    "entity_key",
    "as_of",
    "caller_kind",
    "caller_id",
)

# The types, because a name agreed without one is half a signature. `timestamptz`
# rather than a date: an as-of read that loses the time of day answers a different
# question on the day an investigation concluded.
RECALL_ARG_TYPES: Mapping[str, str] = {
    "entity_keys": "array of `type:value` strings, min 1",
    "entity_key": "string, wrapped into entity_keys",
    "as_of": "timestamptz, default now",
    "caller_kind": "string, default `unknown`",
    "caller_id": "string, default `unknown`",
}

RECALL_REQUIRED_ARGS: Tuple[str, ...] = ("entity_keys",)

# The keys of the returned mapping. One mapping and not a list, so
# `tools_router._rows` does not slice the inner lists into rows of their own and
# lose which list each came from.
RECALL_RESULT_KEYS: Tuple[str, ...] = (
    "keys",
    "as_of",
    "sightings",
    "verdicts",
    "gaps",
    "dropped",
    "ranking",
)

# Provenance sits on every row rather than on the envelope: one read returns rows
# from many investigations, and which one concluded a thing is the whole reason a
# later run trusts it.
#
# `concluded_at` is when the investigation concluded, not when the row was
# written. The Distil polls, so an investigation that ended Monday can be written
# Wednesday carrying Monday's date — inside the freshness predicate, absent from
# the read that ran on Tuesday. Which is why recall journals its rows.
_PROVENANCE: Tuple[str, ...] = (
    "investigation_kind",
    "investigation_id",
    "concluded_at",
)

# One row per entity, investigation and source, so growth tracks hunts rather
# than telemetry volume. Never one row per evidence record.
SIGHTING_FIELDS: Tuple[str, ...] = _PROVENANCE + (
    "entity_key",
    "source_system",
    "hit_count",
    # Aggregated over the evidence in the group. An entity every record naming it
    # could have been named by an adversary cannot clear a branch on its own.
    "attacker_influenceable",
    "window",
)

VERDICT_FIELDS: Tuple[str, ...] = _PROVENANCE + (
    # Stable, because the prose gets re-worded and a key that moves when someone
    # edits a sentence is not a key.
    "hypothesis_id",
    "statement",
    "outcome",
    # The one field here that reaches no ranking function: model text that sounds
    # confident must not be able to move a priority (ADR 0015). Carried for a
    # human reading the run back.
    "rationale",
    # The entities the hypothesis named, typically one to three — not the 38 to
    # 76 its evidence touched, which stay reachable through Sightings as the
    # weaker and truer claim (ADR 0016).
    "subject_entities",
    # True when every source was something an adversary could have authored. Not
    # per-source: what a branch-clearing rule asks is whether anything
    # independent was seen at all.
    "attacker_influenceable_only",
    "trust",
    "window",
    "window_source",
    "sources",
)

# Replaces a flat corroborated list, which cannot express direction: a source
# that weakened a hypothesis and a source that never bore on it are not the same
# row. `source_system` is memory's own column and not a foreign key into either
# producer — a hunt-derived Verdict fills it from the Ledger, a Case-derived one
# from the `data_source` of its Findings — which is why the tier map is keyed
# twice.
# `source_tier` carries #728's vocabulary and is not restated here. A
# `not_evidence` value on one of these rows is a defect rather than a weak row —
# citing a rule catalogue as corroboration is a run treating a lookup as an
# observation — and it is representable so that it is visible.
VERDICT_SOURCE_FIELDS: Tuple[str, ...] = ("source_system", "stance", "source_tier")

# No activity window, which is the reason a Gap is not a Verdict with an empty
# outcome.
GAP_FIELDS: Tuple[str, ...] = _PROVENANCE + (
    "hypothesis_id",
    "statement",
    "disposition",
    "reason",
    "subject_entities",
)

# Both ends inclusive, ISO-8601 with an offset. Separate from a conclusion date
# because a sweep that concluded today about last March is not newly relevant.
WINDOW_FIELDS: Tuple[str, ...] = ("first_seen", "last_seen")

# Why rows are missing, per kind, because the two reasons mean different things
# to the caller: `per_key_cap` means one entity had more history than its share,
# `overall_cap` means the read was broad. A total is the sum and is not restated.
DROPPED_KINDS: Tuple[str, ...] = ("sightings", "verdicts", "gaps")
DROPPED_REASONS: Tuple[str, ...] = ("per_key_cap", "overall_cap")

# Who concluded, as distinct from what the source is. Two axes, because telemetry
# observes and a feed asserts but neither concludes, so an ordered list of the
# four could never place two of them on a Verdict at all.
TRUST_LEVELS: Tuple[str, ...] = ("analyst", "agent")

STANCES: Tuple[str, ...] = ("supports", "weakens", "neither")

# Keyed by kind and id, never by `run_id`: a run-keyed schema cannot represent
# the Case-authored Verdicts the writer split requires. `analyst` is declared and
# written by nothing yet — chat never writes memory, and an analyst thinking
# aloud is not a Verdict.
#
# Wider than `source_tier.InvestigationKind`, deliberately. That enum selects a
# source vocabulary, and an `analyst` investigation names no sources of its own.
INVESTIGATION_KINDS: Tuple[str, ...] = ("hunt", "case", "analyst")

# `proven` and `disproven` come straight through; `inconclusive` covers a
# hypothesis that gathered evidence and did not settle; `handed_off` is terminal
# for the hunt and not an ending of the claim, so it ranks up like a Gap while
# still carrying evidence, a window and sources; `false_positive` arrives only
# from a Case closure.
VERDICT_OUTCOMES: Tuple[str, ...] = (
    "proven",
    "disproven",
    "inconclusive",
    "handed_off",
    "false_positive",
)

# Whether the window was seen or claimed. A retrospective sweep over old archives
# asserts its window, and ranking discounts the weaker one, so it has to be able
# to tell them apart.
WINDOW_SOURCES: Tuple[str, ...] = ("observed", "asserted")

# Why nothing was gathered. A closed set, so the reasons a question went
# unanswered stay apart instead of collapsing into one.
#
# Each value traces to a line of the spec, because a disposition invented here is
# one #731 would write against and nothing would review:
#   deprioritised       — the status map's `parked` arm ("parked | Gap,
#                          deprioritised")
#   no_evidence_gathered — the `inconclusive` and `active` arms, both of which
#                          write "Verdict if evidence was gathered, else Declared
#                          Gap". Also where a `data_starved` run's open questions
#                          land, since such a run "writes normally"
#   budget_exhausted    — "work abandoned for budget is not abandoned forever",
#                          and the `budget_terminated` run terminal
#
# Deliberately not `never_dispatched`: a hypothesis that reached `inconclusive`
# with nothing gathered *was* dispatched, and a value naming the dispatch would
# have made those two indistinguishable. Deliberately not a `no_data_source`
# value either — a tool that could not answer is a **Visibility Gap**, which
# CONTEXT.md keeps distinct from a **Declared Gap** on purpose.
GAP_DISPOSITIONS: Tuple[str, ...] = (
    "deprioritised",
    "no_evidence_gathered",
    "budget_exhausted",
)

# How a queried key is matched against a stored one. Pinned rather than described,
# because the two sides normalise in different languages: the rule lives in
# `services/agent/workflows/hunt/entities.ts` (`defang`, then case-fold) and Python
# has to reproduce it exactly or an exact join quietly misses.
#
# The exception is the part that breaks silently. An ARN's resource part and an
# AWS key id are case-significant, so folding them makes two different principals
# one key — and the join still returns rows, just the wrong ones.
KEY_CASE_SENSITIVE_TYPES: Tuple[str, ...] = ("arn", "aws_key")

# The total order the caps are applied under. A LIMIT over a partial order lets
# Postgres return a different set on identical data, which makes what a run
# remembered nondeterministic and surfaces as a replay diff rather than an error.
# Ties break on the primary key.
RECALL_ORDER = "concluded_at DESC, id ASC"

# Applied as a LATERAL and before the overall cap. A plain trailing LIMIT lets
# one entity present in every hunt — a resolver, a proxy — consume the whole
# budget, which makes memory less useful the more it holds.
RECALL_PER_KEY_CAP = 20
RECALL_OVERALL_CAP = 100

# Copied into the result rather than referenced, because a RunSpec records the
# arch by name and not by version: a replay resolving these afresh would select
# under today's values against rows chosen under the old ones.
#
# Selection only. The order the rows were *presented* in is a fold and is
# deliberately absent — the harness's ranking curve may change without
# invalidating a historical Ledger, which is only true while the event carries
# rows and not an order.
RANKING_KEYS: Tuple[str, ...] = ("order", "per_key_cap", "overall_cap")


def recall_ranking() -> Dict[str, object]:
    """The selection parameters in force, for the result and the read log."""
    return {
        "order": RECALL_ORDER,
        "per_key_cap": RECALL_PER_KEY_CAP,
        "overall_cap": RECALL_OVERALL_CAP,
    }


def empty_dropped() -> Dict[str, Dict[str, int]]:
    """Nothing dropped: zeros rather than an absent key.

    No field in a recall result is nullable and no list is optional. An empty
    list means known-to-be-none, and there is no unknown state to represent --
    which is why an entity with no history is zeros and empty lists, never an
    error.
    """
    return {kind: {reason: 0 for reason in DROPPED_REASONS} for kind in DROPPED_KINDS}


# Two points this contract does not settle, recorded here rather than in a thread
# because a contract's unresolved edges are part of it.
#
# `dropped` diverges from #732's grooming note, which reads `dropped {sightings,
# verdicts, gaps}` and would have an implementer write three integers. #729 asks
# for "the dropped count and why", and one integer cannot carry the why, so the
# leaf is a mapping of the two cap reasons. :func:`empty_dropped` exists so #732
# builds the shape rather than inferring it from the groom. A total is the sum.
#
# Per-entity counts of open questions are what the spec's ranking-inputs section
# owes the harness, and they are the one item that section names which no field
# here carries. They are *nearly* derivable — open questions are Gaps plus
# `handed_off` Verdicts, grouped by `subject_entities` — but the per-key cap
# truncates precisely the entities the count exists to surface, and `dropped` is
# aggregated across the read rather than per key, so a caller cannot tell 20 from
# 60. Resolving it means either a count taken before the caps or per-key drop
# attribution, and both add a key #732's groom does not have. Flagged rather than
# chosen: the ranking is the harness's, so which of the two it wants is theirs to
# say.


# Every read of memory, whoever asked. The harness's Ledger event exists for
# replay and has to live in the Ledger; this log exists for audit, and it is the
# only thing that makes "we can see what it knew" true for a caller that has no
# Ledger. It holds reads rather than facts, so it is the one part of the tier
# that needs a retention policy.
# Column names, not paraphrases: #732 owns the DDL and this is what it creates.
# `row_counts` rather than `returned` because the log holds how many came back per
# kind and not the rows themselves — it is an audit trail, and copying the rows
# into it would make it a second store of facts with its own retention.
READ_LOG_FIELDS: Tuple[str, ...] = (
    "id",
    "ts",
    "caller_kind",
    "caller_id",
    "keys",
    "as_of",
    "row_counts",
    "dropped",
    "ranking",
)

# Stated here because "it needs one" is not a policy. The read log is the one part
# of the tier that has retention at all: it holds lookups, and the facts they
# looked up are kept forever.
READ_LOG_RETENTION_DAYS = 90

# An unattributed read is still worth logging, so the caller fields default
# rather than being required.
UNKNOWN_CALLER = "unknown"
