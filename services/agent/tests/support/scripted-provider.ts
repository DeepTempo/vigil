import { ZERO_TOKENS, type TokenCounts } from "../../contracts/budget.js";
import { ProviderError, type Provider, type Turn, type TurnRequest } from "../../core/provider.js";

export interface ScriptedTurn {
  // What the model asks for on a tool turn.
  calls?: readonly { tool: string; args: string }[];
  content?: string;
  // What the model answers with on the emission turn. A string is sent verbatim,
  // so a test can hand back something the schema will reject.
  emit?: unknown;
  fail?: string;
  tokens?: Partial<TokenCounts>;
}

export type ScriptedProvider = Provider & { readonly requests: readonly TurnRequest[] };

// Stands in for the model and nothing else: the registry, scanner, budget, turn cap
// and approval gate are all real, so a test of the loop is a test of the loop.
export function scriptedProvider(script: readonly ScriptedTurn[], model = "scripted/model"): ScriptedProvider {
  const requests: TurnRequest[] = [];
  let step = 0;

  return {
    model,
    requests,
    turn: async (request: TurnRequest): Promise<Turn> => {
      requests.push(request);
      const next = script[step];
      step += 1;
      if (next === undefined) throw new Error(`the script ran out at turn ${step}`);

      const tokens = { ...ZERO_TOKENS, ...next.tokens };
      if (next.fail !== undefined) throw new ProviderError(next.fail, tokens);

      if (request.emit !== undefined) {
        if (next.emit === undefined) throw new Error(`turn ${step} was asked for an emission the script does not have`);
        const content = typeof next.emit === "string" ? next.emit : JSON.stringify(next.emit);
        return { content, tool_calls: [], tokens };
      }

      const calls = (next.calls ?? []).map((call, index) => ({ id: `c${step}-${index}`, ...call }));
      return { content: next.content ?? "", tool_calls: calls, tokens };
    },
  };
}
