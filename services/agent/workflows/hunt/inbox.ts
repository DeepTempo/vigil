import { actorName } from "./actor.js";
import { newId } from "./ids.js";
import type { Journal } from "./journal.js";
import type { DirectiveQueue } from "./ports.js";
import { DIRECTIVE_KINDS, type BudgetGrant, type Directive, type DirectiveKind } from "./types.js";

// The controller's own voice in the directive stream. The drain tells a queued
// directive from a controller note by id, not by this; it is for the report.
export const CONTROLLER_ACTOR = "controller";

// The stub operator a DEV_MODE deployment attributes to, so the attribution path
// is exercised with auth off rather than skipped. Read here rather than in
export const DEV_ACTOR = "dev-admin";

// Only meaningful for a directive queued from this process — a console answer
// carries the operator its own auth resolved, and passes it explicitly.
export function directiveActor(): string {
  if (process.env["VIGIL_ACTOR"]) return actorName();
  return process.env["DEV_MODE"] === "true" ? DEV_ACTOR : actorName();
}

export class InvalidDirective extends Error {}

// What an extension buys, read out of the operator's own words: "+5 iterations",
// "$10 more", "5 iterations and $2.50". Parsed once at queue time so the ledger
export function parseGrant(text: string): BudgetGrant {
  const iterations = /(\d+(?:\.\d+)?)\s*(?:more\s+)?iterations?/i.exec(text);
  const dollars = /\$\s*(\d+(?:\.\d+)?)|(\d+(?:\.\d+)?)\s*(?:usd|dollars?)/i.exec(text);
  const cost = dollars?.[1] ?? dollars?.[2];

  return {
    iterations: Math.max(0, Math.floor(Number(iterations?.[1] ?? 0))),
    cost_usd: Math.max(0, Number(cost ?? 0)),
  };
}

export function grantOf(directive: Directive): BudgetGrant {
  return directive.grant ?? parseGrant(directive.text);
}

// What a directive may carry beyond its text: which checkpoint it answers, which
// entity it suppresses, which lead it pins. Typed at queue time so the drain
export type DirectiveFields = Partial<
  Pick<Directive, "actor" | "checkpoint_id" | "entity_key" | "question_id" | "hypothesis_id" | "tenant" | "revoke">
>;

// The envelope, checked at the boundary another process writes across. The fields
// a workflow owns are deliberately not checked here — the workflow validates its
// own vocabulary, and a directive that names a checkpoint that does not exist is
// a question for the controller, not a malformed directive.
export function validateDirective(directive: Directive): void {
  if (typeof directive.directive_id !== "string" || directive.directive_id.length === 0) {
    throw new InvalidDirective("a directive with no id cannot be journaled or excluded from the next drain");
  }
  if (!(DIRECTIVE_KINDS as readonly string[]).includes(directive.kind)) {
    throw new InvalidDirective(`unknown directive kind ${String(directive.kind)}`);
  }
  if (typeof directive.actor !== "string" || directive.actor.length === 0) {
    throw new InvalidDirective("a directive with no actor leaves the ledger unable to say who steered the run");
  }
  if (typeof directive.text !== "string") {
    throw new InvalidDirective("a directive's text is what reaches the digest, so it must be a string");
  }
}

// Queues an operator's directive. Async because the queue is shared with every
// other process now, and it throws rather than firing the write off unawaited: an
// enqueue that failed must reach the operator, not vanish.
export async function steer(
  queue: DirectiveQueue,
  runId: string,
  kind: DirectiveKind,
  text: string,
  fields: DirectiveFields = {},
): Promise<Directive> {
  const directive: Directive = {
    directive_id: newId("dir", 4),
    actor: directiveActor(),
    kind,
    text,
    created_at: new Date().toISOString(),
    origin: "inbox",
    ...(kind === "extend" ? { grant: parseGrant(text) } : {}),
    ...fields,
  };
  validateDirective(directive);
  await queue.enqueue(runId, directive);
  return directive;
}

// The controller journaling its own note, so a refusal or a clamped extension
// reaches the next digest through exactly the channel an operator's note uses.
export function journalNote(ledger: Journal, text: string): Directive {
  const directive: Directive = {
    directive_id: newId("dir", 4),
    actor: CONTROLLER_ACTOR,
    kind: "note",
    text,
    created_at: new Date().toISOString(),
    origin: "controller",
  };
  ledger.append({ kind: "directive", payload: directive });
  return directive;
}

// Everything the ledger already holds, whoever wrote it. The controller's own
// notes were never queued, so excluding them costs nothing and keeps this one
// question: has this directive reached the record?
function journaled(ledger: Journal): string[] {
  return ledger.projection.directives.map((directive) => directive.directive_id);
}

// What the next drain would take, without taking it. The hard abort reads this
// between dispatch settlements: an operator who hit abort mid-iteration should
export async function peek(ledger: Journal): Promise<Directive[]> {
  return ledger.queue.pending(ledger.runId, journaled(ledger));
}

// Skips what the ledger already recorded rather than deleting from the queue, so
// a drain interrupted halfway simply re-runs. Only the run holding the ledger
// drains, so the controller stays the sole mutator.
export async function drain(ledger: Journal): Promise<Directive[]> {
  const taken: Directive[] = [];

  for (const directive of await peek(ledger)) {
    try {
      validateDirective(directive);
    } catch (error) {
      // Journaled under its own id, as a controller note: the operator's attempt
      // is on the record, the switch never sees a kind it cannot read, and the
      // refusal happens once rather than on every drain for the rest of the run.
      // Their own words and the kind they asked for carry into the note, because
      // the refusal is the only thing the record will hold of the attempt.
      const said = typeof directive.text === "string" && directive.text.length > 0 ? ` — ${directive.text}` : "";
      ledger.append({
        kind: "directive",
        payload: {
          ...directive,
          kind: "note",
          origin: "controller",
          text: `refused a malformed ${String(directive.kind)} directive: ${(error as Error).message}${said}`,
        },
      });
      continue;
    }
    // Normalised on the way in, not at every read: an extend queued by a writer
    // that does not parse prose still lands on the ledger as numbers, so what was
    // granted reads the same whoever asked. The regex stays defined once, here.
    const journaling =
      directive.kind === "extend" && directive.grant === undefined
        ? { ...directive, grant: grantOf(directive) }
        : directive;

    ledger.append({ kind: "directive", payload: journaling });
    taken.push(journaling);
  }

  return taken;
}
