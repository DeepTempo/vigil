# 15. Memory reorders the frontier and never decides

Date: 2026-08-24

## Status

Accepted

## Context

Episodic memory gives a run access to what earlier runs concluded. The obvious
shape is the useful one: keep a disposition on each entity, and let a hunt read
it. "This host is a known false positive" is one indexed lookup, it is what every
IOC store on the market does, and it would let a run skip work it has already
done.

ADR 0008 sets the bar this has to clear — an untrustworthy detector is not a weak
detector, it is a negative-value one. A stored disposition fails that bar in both
directions, and the failures are symmetric:

**A benign history buries a host.** Three runs confirm that `web-01` plus this
alert is the nightly backup job. In August the host is genuinely compromised, and
the adversary is deliberately working inside the backup window. A disposition
field says benign, the hunt deprioritises it, and the more confident the history
the better the hiding place. Where a system does not look is itself information,
and it is information an adversary can act on.

**A malicious history convicts one.** A real incident in June becomes prior
corroboration in August, so one weak signal is enough to reach a verdict. That
verdict becomes prior corroboration in September. The evidence bar falls every
time, each fall justified by the last, until the host is guilty of anything that
happens near it — which is both an analyst-fatigue problem on remediated hosts and
a cheap way for an adversary to manufacture noise.

There is a third failure with no adversary in it at all. A verdict's rationale is
model-authored prose. Store it, read it back next month as established history,
conclude from it, store that — and a guess has been promoted to a fact by nothing
worse than being written down repeatedly. The harness already refuses this inside
a run: evidence carries `attacker_influenceable`, and a verdict may not stand on
adversary-authored evidence alone. Memory would be a way around that check, one
run at a time.

## Decision

Memory may change **what a run looks at first**. It may never change **what
counts as having found something**.

Five rules carry it, and each is a constraint on the schema or on a function
signature rather than a convention:

1. **No status on an entity.** There is no `disposition`, `is_benign` or
   `reputation` column. "What do we think about this host" is answered by reading
   its **Verdicts** — three concluded benign, all June, one analyst-authored —
   and the current run concludes from **Evidence** it gathered itself. A field
   that can be written is a field something will read as truth.

2. **Ranking returns a permutation of the frontier, never a filter.** Same
   members in, same members out, in a different order. A ranking that can drop a
   member is memory deciding by starvation, which is the same outcome by a quieter
   route. `sorted(in) == sorted(out)` is the whole enforcement.

3. **Recall never contributes to corroboration.** A Verdict needs evidence from
   more than one telemetry domain gathered by the **Investigation** making it.
   Neither a benign nor a malicious history lowers the bar for the next one.

4. **Ranking reads counted facts, never prose.** Sources, dates, outcome,
   corroboration count, trust tier. The rationale is rendered for the lead and
   passed to nothing that computes. The ranking function does not take it as an
   argument, so no amount of confident text can move a hypothesis.

5. **Unanswered questions rank up.** A hypothesis a run left untested becomes a
   **Declared Gap**, and recall surfaces it. A hypothesis repeatedly
   deprioritised accumulates evidence of its own neglect until it surfaces — the
   cross-run half of rule 2, and the reason rule 2 does not have to be perfect
   within a single run.

## Consequences

Prior work cannot strengthen a current verdict, which reads as a loss and is not
one: memory makes a run fast, evidence makes it right, and the value is delivered
before the proof question arises. A confirmed attack on a host in June still puts
that host at the top of August's queue on iteration one instead of iteration
thirty. It simply cannot be one of the two sources August needs.

Rule 1 also decides a boundary that would otherwise be argued column by column.
A supervisory **Fleet Projection** — which runs are live, stalled or spending — has
to carry status, and looks similar enough to episodic memory to invite a merge.
They stay separate stores: a run having a status is not an entity having one, and
a single schema cannot enforce both readings. A Fleet Projection may read episodic
memory; only the distil writes it.

The rules also decide the shape of the tier. Rule 1 makes the store append-only,
which is why as-of queries need no transaction-time column and why the bitemporal
machinery this design originally budgeted for was not built. Rule 4 splits the
Verdict into counted fields and one prose field, and puts the decay curve where a
replay can find the parameters that were in force.
