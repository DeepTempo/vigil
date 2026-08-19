import type { RegisteredTool } from "../contracts/tool.js";

// A grant the loop could not have honoured. Thrown at construction, so a wiring
// mistake surfaces at startup rather than seven turns into a run.
export class RegistryError extends Error {}

// Deny-by-default per role: a role gets what it was granted, never a catalogue.
// MCP registers through this same port, so only a grant widens what a role calls.
export interface Registry {
  granted(role: string): readonly RegisteredTool[];
  get(role: string, id: string): RegisteredTool | undefined;
}

export function registryOf(
  tools: readonly RegisteredTool[],
  grants: Readonly<Record<string, readonly string[]>>,
): Registry {
  const byId = new Map<string, RegisteredTool>();
  for (const tool of tools) {
    if (byId.has(tool.id)) throw new RegistryError(`two tools are registered as ${tool.id}`);
    byId.set(tool.id, tool);
  }

  const roles = new Map<string, readonly RegisteredTool[]>();
  for (const [role, ids] of Object.entries(grants)) roles.set(role, ids.map((id) => resolve(byId, role, id)));

  return {
    granted: (role) => roles.get(role) ?? [],
    get: (role, id) => (roles.get(role) ?? []).find((tool) => tool.id === id),
  };
}

function resolve(byId: ReadonlyMap<string, RegisteredTool>, role: string, id: string): RegisteredTool {
  const tool = byId.get(id);
  if (tool === undefined) throw new RegistryError(`role ${role} is granted ${id}, which is not registered`);
  return tool;
}
