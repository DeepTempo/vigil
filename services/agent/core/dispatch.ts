import type { ToolDispatch } from "./seams.js";

// In-process, which is the whole implementation. It is a port because the next
// one is not: a remote executor sends the tool id and arguments over a wire and
// resolves the same ToolResult, and neither the loop nor a workflow changes.
export const localDispatch: ToolDispatch = { invoke: (tool, args) => tool.invoke(args) };
