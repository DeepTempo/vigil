# Historical hunt ledgers

Ten hunt ledgers, their projections, their derived folds, and one deliberately
torn ledger. `tests/hunt/fold-equivalence.test.ts` replays them.

## Where they come from

The runs are hunts over **BOTS v3** — Splunk's published Boss of the SOC sample
dataset, the fictional "Frothly" brewing company. There is nothing here from a
real network, and the provenance is stated rather than hidden: a fixture whose
origin is a secret cannot be reasoned about.

The ledgers were produced by the `threat-hunt` implementation, which wrote a
JSONL file ledger. `tests/support/historical.ts` maps that shape onto the harness
envelope, so the files stay as they were written.

## Why they are rewritten

`scripts/sanitise-hunt-ledgers.ts` rewrites every identifier. This is **hygiene,
not privacy**: the inputs are published sample data. It buys three things.

- Several hundred `AKIA`-shaped strings and base64 payloads would trip secret
  scanning on every clone.
- Redistributing a third party's dataset verbatim is a licence argument nobody
  needs to have.
- A fixture set that is clean by construction can take a future run without
  anyone having to re-audit the ones already here.

Substitution is 1:1 and consistent across every run, so entity counts,
co-occurrence pair counts and first-sighting are unchanged — which is what
`hasRarePairing`, `introducedRecurring` and therefore `salienceFloor` are
computed from. Ids, seeds and timestamps are carried verbatim, so the digest's
seeded resurfacing selects the same records. Counts, rates and durations in the
analysts' prose are untouched, so the runs still describe what they found.

What deliberately survives: process command lines (the attack narrative — a
pseudonymised `powershell.exe -enc …` records that something ran and nothing
about what), service and role accounts (`NT AUTHORITY\SYSTEM`, `tomcat8`), two
user-agent strings, and two domains that name a *tool* rather than an
observation (`threatfox.abuse.ch`, `schemas.microsoft.com`).

`tests/hunt/fixtures-are-sanitised.test.ts` holds this to an allowlist using the
pipeline's own entity extractor, so what the fold would read as an identifier is
what gets checked. Both halves of the extractor are used: `fromText` over the raw
bytes, and `fromPayload` over the parsed documents — the latter because a `user`
is typed by its payload key and no text pattern can yield one. `pseudonyms.json`
is swept alongside the ledgers.

## Where the goldens come from

`*.projection.json.gz` and `*.folds.json.gz` were written by
`scripts/generate-fold-goldens.ts` driving the **original** file-ledger
implementation over these sanitised inputs — never the implementation under test.
A golden produced by the code it guards pins nothing; it would agree with any
regression the port introduced. See ADR 0012.

The generator was calibrated first: run against the pre-sanitisation ledgers it
reproduces the goldens the original had already committed, which is what
establishes that it drives the original the way the hunt loop did.

Five of the ten runs are near-trivial — a spec, a hypothesis or two, no evidence.
They are worth keeping because they pin the empty and one-record cases, but a
regression in entity ranking will only show up in the other five.

## pseudonyms.json

The mapping, keyed by `sha256("<type>:<value>")` truncated to 16 hex characters.
Keyed by digest for the same reason the fixtures are rewritten at all: a
cleartext map would restate every value removed here, in the same commit.

This is not concealment — the originals are published and the candidate space is
small. It stops the values being *restated*. A later run is sanitised
consistently by hashing its own values and looking them up.

Each replacement is written as the **ledgers** carry it, not as the mapping table
holds it. Some entries map a value to itself — a preserved process, a role
account — and an original still carries values the text pass removes. The ledgers
hold `useradd … -p host0026.example.com`; writing the table's side of that entry
would restate the domain the line started out naming, in the file whose whole
purpose is not to.

**A map over genuinely sensitive data must never be committed at all**, in any
form. This one is committable because its inputs are a public sample dataset.

## Adding a run

```
npx tsx scripts/sanitise-hunt-ledgers.ts --in <real> --out <sanitised> --review /tmp/review.txt
npx tsx scripts/generate-fold-goldens.ts --original <threat-hunt checkout> --ledgers <sanitised> --out <sanitised>
```

Read `--review` before the goldens are cut from it; it is cleartext and must not
be written into this directory. Then check the rewrite preserved what the folds
read:

```
npx tsx scripts/check-sanitised-folds.ts --real <real> --sanitised <sanitised>
```

The original implementation is pinned at commit `2051232` on the `threat-hunt`
lineage.
