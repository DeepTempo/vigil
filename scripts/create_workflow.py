#!/usr/bin/env python3
"""Scaffold a new Vigil workflow directory with a commented WORKFLOW.md template.

Usage:
    python scripts/create_workflow.py <workflow-name>
    python scripts/create_workflow.py phishing-triage
    python scripts/create_workflow.py insider-threat --agents investigator,correlator,reporter
"""

import argparse
import sys
from pathlib import Path

# Resolve repo root relative to this script
REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO_ROOT / "core" / "workflows" / "definitions"

sys.path.insert(0, str(REPO_ROOT))
from core.agents.builtins import AgentId  # noqa: E402

AVAILABLE_AGENTS = [a.value for a in AgentId]


def slugify(name: str) -> str:
    """Convert a name to a valid workflow directory slug."""
    return name.lower().strip().replace(" ", "-").replace("_", "-")


def build_template(workflow_id: str, agents: list[str]) -> str:
    """Generate a commented WORKFLOW.md template."""
    display_name = workflow_id.replace("-", " ").title()

    # The phase list is the definition: agents and tools are read off it, so a
    # template that stated them beside it would be one edit from disagreeing.
    phase_sections = []
    for i, agent in enumerate(agents, 1):
        agent_display = agent.replace("_", " ").title()
        phase_sections.append(
            f"""  - id: phase-{i}
    agent: {agent}
    name: "TODO: name the {agent_display} step"
    tools: [get_finding, list_findings]
    instructions: |
      TODO: Describe what this phase accomplishes.

      1. TODO — describe the first step
      2. TODO — describe the next step

      Hand on: TODO — say what the next phase is given."""
        )

    phases_yaml = "\n\n".join(phase_sections)

    return f"""---
name: {workflow_id}
description: "TODO: Describe what this workflow does in one sentence."
use_case: "TODO: Describe the scenario that triggers this workflow."
trigger_examples:
  - "Run {display_name.lower()} on finding f-20260401-abc123"
  - "TODO: Add another example trigger"
objectives:
  - "TODO: State what this workflow is for"
phases:
{phases_yaml}
---

# {display_name} Workflow

TODO: Write a one-paragraph summary of this workflow — what it does, which agents
it sequences, and what kind of output it produces.

## When to Use

- TODO: Describe situation 1
- TODO: Describe situation 2

## Example Invocation

```
User: "Run {display_name.lower()} on finding f-20260401-abc123"
```

## Expected Output

```json
{{
  "workflow": "{workflow_id}",
  "phases_completed": [{", ".join(f'"{a}"' for a in agents)}],
  "TODO": "Fill in the expected output structure"
}}
```
"""


def main():
    parser = argparse.ArgumentParser(
        description="Scaffold a new Vigil workflow with a WORKFLOW.md template.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""\
Available agents: {', '.join(AVAILABLE_AGENTS)}

Examples:
  python scripts/create_workflow.py phishing-triage
  python scripts/create_workflow.py insider-threat --agents investigator,correlator,reporter
""",
    )
    parser.add_argument(
        "name",
        help="Workflow name (e.g. phishing-triage). Used as the directory name.",
    )
    parser.add_argument(
        "--agents",
        default="triage,investigator,responder,reporter",
        help="Comma-separated list of agents for the workflow (default: triage,investigator,responder,reporter).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing WORKFLOW.md if it already exists.",
    )

    args = parser.parse_args()

    workflow_id = slugify(args.name)
    agents = [a.strip() for a in args.agents.split(",")]

    # Validate agents
    invalid = [a for a in agents if a not in AVAILABLE_AGENTS]
    if invalid:
        print(f"Error: Unknown agent(s): {', '.join(invalid)}", file=sys.stderr)
        print(f"Available agents: {', '.join(AVAILABLE_AGENTS)}", file=sys.stderr)
        sys.exit(1)

    # Create workflow directory
    workflow_dir = WORKFLOWS_DIR / workflow_id
    workflow_file = workflow_dir / "WORKFLOW.md"

    if workflow_file.exists() and not args.force:
        print(f"Error: {workflow_file} already exists. Use --force to overwrite.", file=sys.stderr)
        sys.exit(1)

    workflow_dir.mkdir(parents=True, exist_ok=True)

    # Write template
    template = build_template(workflow_id, agents)
    workflow_file.write_text(template, encoding="utf-8")

    print(f"Created {workflow_file.relative_to(REPO_ROOT)}")
    print()
    print("Next steps:")
    print(f"  1. Edit {workflow_file.relative_to(REPO_ROOT)} — replace the TODOs")
    print(f"  2. Say \"Run {workflow_id} on finding <id>\" in the Vigil chat")
    print()
    print(f"Available agents: {', '.join(AVAILABLE_AGENTS)}")


if __name__ == "__main__":
    main()
