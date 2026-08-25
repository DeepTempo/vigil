import type { ToolDispatch } from "./seams.js";

// In-process, the whole implementation. A port because the next one is remote and
// resolves the same ToolResult, changing neither the loop nor a workflow.
export const localDispatch: ToolDispatch = { invoke: (tool, args) => tool.invoke(args) };
