import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { archFor, registeredKinds } from "./arch/registry.js";
import type { RunKind } from "./contracts/events.js";
import { nullMemory, recalling } from "./core/memory.js";
import type { Memory, State } from "./core/seams.js";
import { assembleSpec, loadArch, parseConfig, parsePlaybook, SpecError, type Playbook, type RunSpec } from "./core/spec.js";
import { chatEvents, sse } from "./workflows/chat/sse.js";
import { runChat, type Turn } from "./workflows/chat/workflow.js";
import { harnessFor, type HarnessFactory } from "./harness.js";

const PATH = "/chat/stream";
// A conversation is prose and a config, not an upload. Anything larger is a
// mistake or an attack, and either way it is refused before it is parsed.
const MAX_BODY = 1_000_000;

export interface ChatRequest {
  run_id: string;
  turns: readonly Turn[];
  // Resolved by the caller, which is the side that knows what an agent is. It
  // layers onto the arch prompt rather than replacing the house rules.
  system_prompt: string;
  // The config layer as YAML: model, budgets, runtime and the tools this
  // conversation may reach. Assembled per request, so it arrives per request.
  config: string;
  parent_run_id?: string;
}

export function chatSpec(request: ChatRequest): RunSpec {
  const entry = archFor("chat");
  const playbook = parsePlaybook("");
  return assembleSpec({
    arch: loadArch(entry.arch, entry.actions),
    playbook: directed(playbook, request.system_prompt),
    config: parseConfig(request.config),
    prompt: "",
  });
}

// Through the directive layer the arch already has, so the caller's prompt is
// appended to the house rules rather than swapped for them.
function directed(playbook: Playbook, prompt: string): Playbook {
  return prompt.trim() === "" ? playbook : { ...playbook, directives: { ...playbook.directives, lead: prompt } };
}

// What the parent carries forward, if it carries anything. An unknown kind, an
// absent ledger and a kind with no renderer all recall nothing rather than fail.
export async function memoryFor(state: State, parentRunId: string | undefined): Promise<Memory> {
  if (parentRunId === undefined || parentRunId === "") return nullMemory;
  // Off the envelope rather than the seq-0 payload, whose shape depends on which
  // entry point opened the run. run_kind is on every event either way.
  const [opened] = await state.read(parentRunId);
  if (opened === undefined || !registeredKinds().includes(opened.run_kind)) return nullMemory;

  const notes = archFor(opened.run_kind).notes;
  return notes === undefined ? nullMemory : recalling(notes(state, parentRunId));
}

export async function streamChat(state: State, request: ChatRequest, res: ServerResponse, build: HarnessFactory = harnessFor): Promise<void> {
  // Assembling the spec is inside the try because it is the likeliest thing to
  // refuse: the headers are already sent, so a refusal is a frame or it is nothing.
  try {
    const spec = chatSpec(request);
    const harness = build("chat" as RunKind, spec, state, await memoryFor(state, request.parent_run_id));
    const stream = runChat(harness, { run_id: request.run_id, spec, turns: request.turns });

    for (;;) {
      const next = await stream.next();
      if (next.done) break;
      for (const event of chatEvents(next.value)) res.write(sse(event));
      // The reader is gone, so the generator is finalised here rather than after
      // a whole answer nobody will read: its finally still journals the spend.
      if (res.writableEnded || res.destroyed) return void (await stream.return(undefined as never));
    }
  } catch (error) {
    res.write(sse({ error: error instanceof Error ? error.message : String(error) }));
  }
  res.end();
}

// Both checks or neither, the same trade Python's authorise makes: a shared secret
// on a public bind is one leak from open, a loopback bind alone trusts every
// process on the box.
function authorised(req: IncomingMessage): boolean {
  const host = req.socket.remoteAddress ?? "";
  if (!(host === "127.0.0.1" || host === "::1" || host === "::ffff:127.0.0.1")) return false;
  const expected = process.env["AGENT_INTERNAL_TOKEN"] ?? process.env["VIGIL_TOOLS_TOKEN"] ?? "";
  return expected !== "" && req.headers.authorization === `Bearer ${expected}`;
}

async function body(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw new SpecError(`a chat request may not exceed ${MAX_BODY} bytes`);
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function refuse(res: ServerResponse, status: number, detail: string): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify({ detail }));
}

export function chatServer(state: State, build: HarnessFactory = harnessFor): Server {
  return createServer((req, res) => {
    void (async () => {
      if (req.method !== "POST" || (req.url ?? "") !== PATH) return refuse(res, 404, `no such route: ${req.method} ${req.url}`);
      if (!authorised(req)) return refuse(res, 401, "loopback and a valid internal token, or neither");

      let request: ChatRequest;
      try {
        request = JSON.parse(await body(req)) as ChatRequest;
      } catch (error) {
        return refuse(res, 400, error instanceof Error ? error.message : String(error));
      }

      // Headers before the first token, so the reader is streaming rather than
      // buffering a response it will be handed all at once.
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
      await streamChat(state, request, res, build);
    })();
  });
}

export function chatPort(): number {
  return Number(process.env["AGENT_HTTP_PORT"] ?? 6989);
}
