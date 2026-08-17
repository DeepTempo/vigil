// Writes the fold goldens by running the *original* file-ledger implementation
// over a ledger set -- never the implementation under test. A golden produced by
// the code it guards pins nothing: it would agree with any regression the port
// introduced. See ADR 0012.
//
// The original lives outside this tree, in the threat-hunt lineage, so it is
// loaded by path rather than imported. Its modules need only `yaml` beyond node
// builtins; link that into <original>/node_modules and tsx does the rest.
//
// Calibrate before trusting it: --check against the goldens the original already
// produced must be clean, which proves this script drives it the same way the
// hunt loop did. Only then point it at a different ledger set.
//
//   npx tsx scripts/generate-fold-goldens.ts --original <root> --ledgers <dir> --check <dir>
//   npx tsx scripts/generate-fold-goldens.ts --original <root> --ledgers <dir> --out <dir>

import { gunzipSync, gzipSync } from "node:zlib";
import { readdirSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, resolve } from "node:path";

type Original = {
  fold: (events: readonly unknown[]) => Projection;
  buildDigest: (projection: Projection, iteration: number, policy: unknown) => unknown;
  evidenceStrength: (projection: Projection, hypothesisId: string) => unknown;
  buildReport: (projection: Projection) => unknown;
};

type Projection = {
  hunt: { iteration: number; spec: { digest: unknown } };
  hypotheses: Map<string, unknown>;
  questions: Map<string, unknown>;
  evidence: Map<string, unknown>;
  dispatches: Map<string, unknown>;
  checkpoints: Map<string, unknown>;
};

const loadOriginal = async (root: string): Promise<Original> => {
  const at = (name: string): string => resolve(root, "ai", name);
  const [ledger, digest, strength, report] = await Promise.all([
    import(at("ledger.ts")),
    import(at("digest.ts")),
    import(at("strength.ts")),
    import(at("report.ts")),
  ]);
  return {
    fold: ledger.fold,
    buildDigest: digest.buildDigest,
    evidenceStrength: strength.evidenceStrength,
    buildReport: report.buildReport,
  };
};

const eventsOf = (text: string): unknown[] =>
  text
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as unknown);

// The same Map conversion the gate applies, so this compares implementations
// rather than the fact that a Map does not survive JSON.
const comparable = (projection: Projection): unknown =>
  JSON.parse(
    JSON.stringify({
      ...projection,
      hypotheses: Object.fromEntries(projection.hypotheses),
      questions: Object.fromEntries(projection.questions),
      evidence: Object.fromEntries(projection.evidence),
      dispatches: Object.fromEntries(projection.dispatches),
      checkpoints: Object.fromEntries(projection.checkpoints),
    }),
  );

const derived = (original: Original, projection: Projection): unknown =>
  JSON.parse(
    JSON.stringify({
      digest: original.buildDigest(projection, projection.hunt.iteration, projection.hunt.spec.digest),
      strength: Object.fromEntries(
        [...projection.hypotheses.keys()].map((id) => [id, original.evidenceStrength(projection, id)]),
      ),
      report: original.buildReport(projection),
    }),
  );

// First differing path, not a boolean: on a calibration miss the path is the
// whole diagnosis.
const firstDifference = (a: unknown, b: unknown, path = ""): string | null => {
  if (a === b) return null;
  if (a === null || b === null || typeof a !== "object" || typeof b !== "object")
    return `${path || "<root>"}: ${JSON.stringify(a)} != ${JSON.stringify(b)}`;
  if (Array.isArray(a) !== Array.isArray(b)) return `${path}: array vs object`;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return `${path}: length ${a.length} != ${b.length}`;
    for (const [index, item] of a.entries()) {
      const found = firstDifference(item, b[index], `${path}[${index}]`);
      if (found !== null) return found;
    }
    return null;
  }
  const left = a as Record<string, unknown>;
  const right = b as Record<string, unknown>;
  const keys = [...new Set([...Object.keys(left), ...Object.keys(right)])];
  for (const key of keys) {
    if (!(key in left)) return `${path}.${key}: missing on the left`;
    if (!(key in right)) return `${path}.${key}: missing on the right`;
    const found = firstDifference(left[key], right[key], `${path}.${key}`);
    if (found !== null) return found;
  }
  return null;
};

const parseArgs = (): { original: string; ledgers: string; out?: string; check?: string } => {
  const args = process.argv.slice(2);
  const at = (flag: string): string | undefined => {
    const index = args.indexOf(flag);
    return index === -1 ? undefined : args[index + 1];
  };
  const original = at("--original");
  const ledgers = at("--ledgers");
  if (original === undefined || ledgers === undefined) throw new Error("need --original and --ledgers");
  const out = at("--out");
  const check = at("--check");
  if ((out === undefined) === (check === undefined)) throw new Error("need exactly one of --out, --check");
  return { original, ledgers, ...(out === undefined ? {} : { out }), ...(check === undefined ? {} : { check }) };
};

const main = async (): Promise<void> => {
  const { original: root, ledgers, out, check } = parseArgs();
  const original = await loadOriginal(root);

  const runs = readdirSync(ledgers)
    .filter((name) => name.endsWith(".jsonl.gz") && !name.includes(".corrupt."))
    .map((name) => name.replace(".jsonl.gz", ""))
    .sort();

  if (out !== undefined) mkdirSync(out, { recursive: true });

  let failures = 0;
  for (const run of runs) {
    const text = gunzipSync(readFileSync(join(ledgers, `${run}.jsonl.gz`))).toString("utf8");
    const projection = original.fold(eventsOf(text));
    const produced: [string, unknown][] = [
      [`${run}.projection.json.gz`, comparable(projection)],
      [`${run}.folds.json.gz`, derived(original, projection)],
    ];

    for (const [name, value] of produced) {
      if (out !== undefined) {
        writeFileSync(join(out, name), gzipSync(Buffer.from(JSON.stringify(value))));
        continue;
      }
      const expected = JSON.parse(gunzipSync(readFileSync(join(check as string, name))).toString("utf8")) as unknown;
      const difference = firstDifference(value, expected);
      if (difference !== null) failures += 1;
      console.log(`${difference === null ? "ok  " : "FAIL"} ${name}${difference === null ? "" : `  ${difference}`}`);
    }
  }

  if (out !== undefined) {
    console.log(`wrote ${runs.length * 2} goldens to ${out}`);
    return;
  }
  console.log(failures === 0 ? `\ncalibrated: ${runs.length} runs reproduce their goldens` : `\n${failures} mismatch(es)`);
  if (failures > 0) process.exitCode = 1;
};

await main();
