import { describe, expect, it } from "vitest";
import { assembleSpec, loadArch, parseConfig, parsePlaybook } from "../../core/spec.js";
import { archFor } from "../../arch/registry.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const FIXTURES = join(import.meta.dirname, "..", "fixtures");

// An arch is versioned and shared; a tool id belongs to a deployment. So the arch
// asks for a capability and the config says what answers it here.
function specWith(configYaml: string) {
  const entry = archFor("hunt");
  return assembleSpec({
    arch: loadArch(entry.arch, entry.actions),
    playbook: parsePlaybook(readFileSync(join(FIXTURES, "hunt.playbook.yaml"), "utf8"), entry.owned),
    config: parseConfig(configYaml, entry.owned),
    prompt: "go",
  });
}

const BASE = readFileSync(join(FIXTURES, "hunt.config.yaml"), "utf8");

describe("binding what a role needs to what a deployment has", () => {
  it("grants the tool that provides the capability", () => {
    const spec = specWith(BASE);
    expect(spec.roles.workers["network_analyst"]?.tools).toContain("splunk_search");
  });

  // The case this exists for: a deployment with no telemetry search loses that
  // tool and still runs, rather than failing to build a spec at all.
  it("drops a capability nothing provides rather than refusing the run", () => {
    const withoutSiem = BASE.replace("    provides: telemetry_search\n", "");
    const spec = specWith(withoutSiem);

    expect(spec.roles.workers["network_analyst"]?.tools).not.toContain("splunk_search");
    expect(spec.roles.workers["threat_hunter"]?.tools).toContain("search_findings");
  });

  // Two deployments, two names, one arch. Nothing in the arch changes.
  it("binds the same capability to whatever this deployment calls it", () => {
    const elastic = BASE.replace("id: splunk_search", "id: elastic_search");
    expect(specWith(elastic).roles.workers["network_analyst"]?.tools).toContain("elastic_search");
  });

  it("keeps a tool the arch named outright", () => {
    expect(specWith(BASE).roles.lead?.tools).toEqual(["expand"]);
  });
});
