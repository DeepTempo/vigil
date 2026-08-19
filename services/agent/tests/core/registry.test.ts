import { describe, expect, it } from "vitest";
import { registryOf, RegistryError } from "../../core/registry.js";
import { defineTool, type RegisteredTool } from "../../contracts/tool.js";

function tool(id: string): RegisteredTool {
  return defineTool(
    {
      id,
      description: id,
      parameters: {},
      execute: async () => ({ ok: true, rows: [], rowCount: 0, capped: false, sourceSystem: "test" }),
    },
    { maxRows: 10, timeoutMs: 100 },
  );
}

describe("the tool registry", () => {
  it("gives a role only what it was granted", () => {
    const registry = registryOf([tool("read"), tool("write")], { reader: ["read"] });
    expect(registry.granted("reader").map((granted) => granted.id)).toEqual(["read"]);
    expect(registry.get("reader", "write")).toBeUndefined();
  });

  // Deny-by-default: an unlisted role is not an error at construction, because a
  // role that calls no tools is legitimate. It gets nothing, not everything.
  it("gives an ungranted role nothing", () => {
    const registry = registryOf([tool("read")], { reader: ["read"] });
    expect(registry.granted("lead")).toEqual([]);
    expect(registry.get("lead", "read")).toBeUndefined();
  });

  it("refuses a grant naming a tool that does not exist", () => {
    expect(() => registryOf([tool("read")], { reader: ["read", "erase"] })).toThrow(RegistryError);
  });

  // Two tools under one id means the loop silently calls whichever won, and the
  // grant that named it no longer says what a role may do.
  it("refuses two registrations of the same id", () => {
    expect(() => registryOf([tool("read"), tool("read")], {})).toThrow(RegistryError);
  });
});
