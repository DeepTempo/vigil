import { defineTool, type RegisteredTool } from "../../contracts/tool.js";

const MAX_STEP = 5;

// The whole capability of the workflow: it adds up. A real adapter would reach a
// backend, but the point here is that the harness cannot tell the difference.
export function bumpTool(): RegisteredTool {
  let count = 0;
  return defineTool(
    {
      id: "bump",
      description: "Add a number to the running count and return the new total.",
      parameters: {
        type: "object",
        additionalProperties: false,
        required: ["by"],
        properties: { by: { type: "integer", minimum: 1, maximum: MAX_STEP } },
      },
      execute: async (args) => {
        const by = args["by"];
        if (typeof by !== "number" || !Number.isInteger(by) || by < 1 || by > MAX_STEP) {
          return { ok: false, failure: { kind: "invalid_args", detail: `by must be an integer from 1 to ${MAX_STEP}` } };
        }
        count += by;
        return { ok: true, rows: [{ count }], rowCount: 1, capped: false, sourceSystem: "counter" };
      },
    },
    { maxRows: 1, timeoutMs: 1_000 },
  );
}
