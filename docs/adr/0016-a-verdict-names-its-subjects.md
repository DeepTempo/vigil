# 16. A Verdict names its subjects, not its evidence's entities

Date: 2026-08-26

## Status

Accepted

## Context

A **Verdict** answers one **Hypothesis**, and **Entity Recall** finds it by joining
on entity keys. So a Verdict has to name entities, and the obvious set is the one
its evidence touched — every host, address and hash the run gathered while testing
that hypothesis. That is what makes the lookup complete: ask about any entity
involved in a past conclusion and the conclusion comes back.

The committed fixtures say how large that set actually is. Counting distinct
entity keys across the evidence linked to each hypothesis, for the hypotheses that
gathered any:

    4, 4, 7, 38, 55, 55, 76

The median is not three to five. A hypothesis routinely touches forty to seventy
entities, and the shape of that tail is not accidental — a run pivots through
infrastructure, and infrastructure is shared. The resolver, the proxy, the domain
controller and the jump host appear in almost every hunt because they appear in
almost every packet.

Ranking reads a Verdict's counted facts, and the strongest of those is its outcome.
If a Verdict lists all seventy, then a confirmed intrusion tags seventy entities as
having been part of one. Sixty-seven of them were passing traffic. The next hunt
recalls "this address participated in a proven compromise" about a DNS resolver,
ranks it up, and spends its first decisions there.

This is the hot-key problem relocated. Capping sightings per key keeps a busy
entity from consuming the recall budget; it does nothing about a busy entity
inheriting the weight of every conclusion it was ever near. And unlike the
storage version, this one degrades as memory fills: the more confirmed incidents
accumulate, the more of them the shared infrastructure has been "part of".

## Decision

A **Verdict** names its **subject** entities only — those the Hypothesis is about,
extracted from its statement, typically one to three.

The entities its evidence touched are not recorded on the Verdict. They are
already recorded, completely, as **Sightings**: one row per entity, investigation
and source. So an incidental entity remains reachable, by a different and weaker
route — *seen during a run that concluded X*, rather than *part of the conclusion
that X*.

The weaker claim is the true one. A resolver that carried the traffic was not a
subject of the finding, and a schema that cannot tell the two apart will be read
as though it could.

## Consequences

The array on a Verdict goes back to being the right shape, because it finally
holds the right thing. No junction table with a role column, and no per-entity
weighting rule for the ranking to get right.

What is lost is the hypothesis-level link for incidental entities. "Which
conclusions did this address contribute evidence to" is no longer one join; it is
"which runs saw it" followed by "what did those runs conclude". For ranking that
is the more honest signal anyway, but it is a real reduction in precision and a
query that would have been trivial is now two hops.

Subject extraction runs over the Hypothesis statement with the harness's existing
typed extractor — no model call, and the same rules that produce **Entity Keys**
everywhere else, so subjects join against Sightings by construction. A Hypothesis
whose statement names no entity therefore yields a Verdict that Entity Recall
cannot reach. "Is there any lateral movement at all" is a real question of that
shape. Those Verdicts are reachable only through **Narrative Recall**, which is
the last thing built — so until it exists, they are written and not read.

The decision is reversible while the **Ledgers** exist, since the evidence's
entities can be re-derived and a distil version bump would rewrite the rows. It
stops being reversible if ledger retention ever lands, which is the argument for
recording it now rather than discovering the constraint later.

## Amendment (#733): a Case names its subjects through its IOCs

The rule above says *extracted from the Hypothesis statement with the harness's
typed extractor*. A Case is a Hypothesis whose statement is its title, and the
extractor is TypeScript. Re-implementing it in Python is the second
implementation that drifts while only one is gated — the same argument the
**Distil** makes for not re-folding a ledger — and a Case title yields almost
nothing to extract in any case.

So for `investigation_kind = case`, subjects are the Case's **IOCs**, keyed with
`entity_key(ioc_type, value)`. These arrive already typed, so no extraction runs
at all, and they are analyst-curated, which holds the "typically one to three"
bound better than `Finding.entity_context` across a Case's Findings would — that
would scoop exactly the shared infrastructure this ADR exists to keep off a
Verdict.

Two bounds the extractor got for free and this does not, so both are stated:

- `case_iocs.ioc_type` is free text and the console offers kinds a key cannot
  name. A type outside `ENTITY_KEY_TYPES` is dropped — a `mutex` key is one no
  reader will ever query, and an unqueryable key reads as an entity nobody has
  looked at rather than as a bad write.
- An IOC list has no sentence to bound it. `VERDICT_SUBJECT_CAP` (12) bounds it
  instead, and the writer logs what it dropped: a silently truncated subject
  list reads as a Verdict that named fewer entities.

The rule for hunts is unchanged. This is the first place in the system where
`subject_entities` is non-empty: #731 shipped with all eighteen hunt Verdicts
naming none, because the statements are playbook templates naming entity classes
rather than values.
