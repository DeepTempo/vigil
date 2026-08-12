"""Workflows service for discovering, parsing, and executing WORKFLOW.md workflow definitions."""

import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from core.agents.queue import new_run_id

logger = logging.getLogger(__name__)

# What a workflow definition runs as, and how a job names one. Both belong to the
# agent layer's vocabulary, so they are stated here once rather than inline.
COMPOSE_RUN_KIND = "compose"
WORKFLOW_SCHEME = "workflow:"


# Real YAML rather than the regex reader this replaced. That reader could not carry
# a phase list, and PyYAML has been a declared dependency the whole time it avoided it.
def _parse_yaml_frontmatter(content: str) -> Dict[str, Any]:
    match = re.match(r"^---\s*\n(.*?)\n---\s*(?:\n|$)", content, re.DOTALL)
    if not match:
        return {}

    try:
        parsed = yaml.safe_load(match.group(1))
    except yaml.YAMLError as exc:
        logger.warning("unreadable workflow front matter: %s", exc)
        return {}

    return parsed if isinstance(parsed, dict) else {}


def _get_frontmatter_end(content: str) -> int:
    """Get the character index where frontmatter ends and body begins."""
    match = re.match(r"^---\s*\n(.*?)\n---\s*(?:\n|$)", content, re.DOTALL)
    if match:
        return match.end()
    return 0


class WorkflowDefinition:
    """Represents a parsed workflow from a WORKFLOW.md file."""

    def __init__(
        self,
        workflow_id: str,
        file_path: Optional[Path],
        metadata: Dict[str, Any],
        body: str,
        source: str = "file",
    ):
        self.id = workflow_id
        self.file_path = file_path
        self.metadata = metadata
        self.body = body
        self.source = source  # "file" or "custom"

    @property
    def name(self) -> str:
        return self.metadata.get("name", self.id)

    @property
    def description(self) -> str:
        return self.metadata.get("description", "")

    @property
    def phases(self) -> List[Dict[str, Any]]:
        phases = self.metadata.get("phases") or []
        return phases if isinstance(phases, list) else []

    # Derived, never restated: the phase list already says which agents run and
    # in what order, and a second copy is one edit away from disagreeing with it.
    @property
    def agents(self) -> List[str]:
        seen: List[str] = []
        for phase in self.phases:
            agent = (phase or {}).get("agent") or (phase or {}).get("agent_id")
            if agent and agent not in seen:
                seen.append(agent)
        return seen

    @property
    def tools_used(self) -> List[str]:
        seen: List[str] = []
        for phase in self.phases:
            for tool in (phase or {}).get("tools") or []:
                if tool not in seen:
                    seen.append(tool)
        return seen

    @property
    def use_case(self) -> str:
        return self.metadata.get("use_case", "")

    @property
    def trigger_examples(self) -> List[str]:
        examples = self.metadata.get("trigger_examples", [])
        if isinstance(examples, str):
            return [examples]
        return examples

    def to_dict(self, include_body: bool = False) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        result = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "agents": self.agents,
            "tools_used": self.tools_used,
            "use_case": self.use_case,
            "trigger_examples": self.trigger_examples,
            "source": self.source,
        }
        if include_body:
            result["body"] = self.body
        # Custom workflows carry structured phases for the builder UI
        if "phases" in self.metadata:
            result["phases"] = self.metadata["phases"]
        return result


def _custom_workflow_to_definition(wf: Dict[str, Any]) -> WorkflowDefinition:
    """
    Adapt a database-backed custom workflow dict into a WorkflowDefinition so
    that existing execution code (build_execution_prompt, execute_workflow)
    can consume it without changes.
    """
    phases = wf.get("phases") or []

    # The same key set a file-based playbook carries, so both resolve identically
    # and agents/tools stay derived from the phases rather than stated beside them.
    metadata = {
        "name": wf.get("name", wf.get("workflow_id")),
        "description": wf.get("description", ""),
        "use_case": wf.get("use_case", ""),
        "trigger_examples": wf.get("trigger_examples") or [],
        "phases": phases,
    }

    body = _render_custom_workflow_body(wf, phases)
    return WorkflowDefinition(
        workflow_id=wf["workflow_id"],
        file_path=None,
        metadata=metadata,
        body=body,
        source="custom",
    )


def _render_custom_workflow_body(
    wf: Dict[str, Any], phases: List[Dict[str, Any]]
) -> str:
    """Render a markdown body from structured phases, compatible with
    build_execution_prompt()'s template."""
    lines: List[str] = []
    lines.append(f"# {wf.get('name', wf.get('workflow_id'))}")
    if wf.get("description"):
        lines.append("")
        lines.append(wf["description"])
    lines.append("")
    lines.append("## Agent Sequence")
    lines.append("")
    for phase in phases:
        order = phase.get("order", "?")
        name = phase.get("name", f"Phase {order}")
        agent = phase.get("agent_id", "")
        lines.append(f"### Phase {order}: {name} ({agent})")
        if phase.get("purpose"):
            lines.append("")
            lines.append(f"**Purpose:** {phase['purpose']}")
        tools = phase.get("tools") or []
        if tools:
            lines.append("")
            lines.append("**Tools:** " + ", ".join(f"`{t}`" for t in tools))
        steps = phase.get("steps") or []
        if steps:
            lines.append("")
            lines.append("**Steps:**")
            for i, step in enumerate(steps, start=1):
                lines.append(f"{i}. {step}")
        if phase.get("expected_output"):
            lines.append("")
            lines.append(f"**Output:** {phase['expected_output']}")
        if phase.get("approval_required"):
            lines.append("")
            lines.append("**Approval required before executing this phase.**")
        lines.append("")
    return "\n".join(lines).strip()


class WorkflowsService:
    """Service for discovering, parsing, and executing workflow definitions."""

    def __init__(self, workflows_dir: Optional[Path] = None):
        """
        Initialize workflows service.

        Args:
            workflows_dir: Directory containing workflow definitions
                (default: the bundled ``core/workflows/definitions/``)
        """
        if workflows_dir is None:
            workflows_dir = Path(__file__).resolve().parent / "definitions"

        self.workflows_dir = Path(workflows_dir)
        self._cache: Dict[str, WorkflowDefinition] = {}
        self._cache_loaded_at: Optional[datetime] = None

        # Load workflows on init
        self._load_workflows()

    def _load_workflows(self):
        """Discover and parse all WORKFLOW.md files from the workflows directory."""
        self._cache.clear()

        if not self.workflows_dir.exists():
            logger.warning(f"Workflows directory not found: {self.workflows_dir}")
            return

        for workflow_dir in sorted(self.workflows_dir.iterdir()):
            if not workflow_dir.is_dir():
                continue

            workflow_file = workflow_dir / "WORKFLOW.md"
            if not workflow_file.exists():
                continue

            try:
                content = workflow_file.read_text(encoding="utf-8")
                metadata = _parse_yaml_frontmatter(content)
                body_start = _get_frontmatter_end(content)
                body = content[body_start:].strip()

                workflow_id = workflow_dir.name
                workflow = WorkflowDefinition(
                    workflow_id=workflow_id,
                    file_path=workflow_file,
                    metadata=metadata,
                    body=body,
                )

                self._cache[workflow_id] = workflow
                logger.info(f"Loaded workflow: {workflow_id} ({workflow.name})")

            except Exception as e:
                logger.error(f"Error loading workflow from {workflow_file}: {e}")

        self._cache_loaded_at = datetime.now()
        logger.info(f"Loaded {len(self._cache)} workflows from {self.workflows_dir}")

    def reload(self):
        """Force reload all workflows from disk."""
        self._load_workflows()

    def _get_custom_workflow(self, workflow_id: str) -> Optional[WorkflowDefinition]:
        """Fetch a single custom workflow from the database by ID."""
        try:
            from core.workflows.custom_workflow_service import \
                get_custom_workflow_service

            raw = get_custom_workflow_service().get(workflow_id)
        except Exception as e:
            logger.debug(f"Custom workflow lookup failed for {workflow_id}: {e}")
            return None
        if not raw or not raw.get("is_active", True):
            return None
        return _custom_workflow_to_definition(raw)

    def _list_custom_workflows(self) -> List[WorkflowDefinition]:
        """List active custom workflows from the database."""
        try:
            from core.workflows.custom_workflow_service import \
                get_custom_workflow_service

            rows = get_custom_workflow_service().list(active_only=True)
        except Exception as e:
            logger.debug(f"Custom workflow listing failed: {e}")
            return []
        return [_custom_workflow_to_definition(r) for r in rows]

    def list_workflows(self) -> List[Dict[str, Any]]:
        """
        Return metadata for all discovered workflows, merging file-based and
        database-backed custom workflows. Custom workflows are listed first.
        """
        custom = [
            wf.to_dict(include_body=False) for wf in self._list_custom_workflows()
        ]
        file_based = [wf.to_dict(include_body=False) for wf in self._cache.values()]
        return custom + file_based

    def get_workflow(self, workflow_id: str) -> Optional[WorkflowDefinition]:
        """Get a specific workflow by ID (custom workflows take precedence)."""
        custom = self._get_custom_workflow(workflow_id)
        if custom:
            return custom
        return self._cache.get(workflow_id)

    def get_workflow_dict(
        self, workflow_id: str, include_body: bool = True
    ) -> Optional[Dict[str, Any]]:
        """Get a specific workflow as a dictionary."""
        workflow = self.get_workflow(workflow_id)
        if workflow:
            return workflow.to_dict(include_body=include_body)
        return None

    # The whole of execution. The playbook decides the order, the agent layer runs
    # it, and this enqueues the run and hands back the id the UI follows.
    async def execute_workflow(
        self,
        workflow_id: str,
        parameters: Dict[str, Any],
        triggered_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Start a workflow as a compose run on the agent layer.

        Returns ``{success, status: "queued", run_id, job_id}``. Progress
        and the outcome are read back through the run record, which the
        agent layer mirrors as each phase completes.
        """
        from core.agents.queue import build_start_job, enqueue_run
        from core.workflows.workflow_run_service import \
            get_workflow_run_service

        workflow = self.get_workflow(workflow_id)
        if not workflow:
            return {"success": False, "error": f"Workflow not found: {workflow_id}"}
        # Caught here as well as in the resolver, so a definition with nothing to
        # run is refused before it leaves a run record behind.
        if not workflow.phases:
            return {
                "success": False,
                "error": f"Workflow declares no phases: {workflow_id}",
            }

        workflow_dict = workflow.to_dict(include_body=False)
        run_service = get_workflow_run_service()
        # One id for one run: the workflow run record and the agent ledger are two
        # views of the same thing, so a mirrored phase needs no id translation.
        run_id = run_service.begin_run(
            workflow_id=workflow.id,
            workflow_name=workflow.name,
            workflow_source=workflow_dict.get("source", "file"),
            workflow_version=workflow_dict.get("version"),
            trigger_context=dict(parameters or {}),
            triggered_by=triggered_by,
            run_id=new_run_id(),
        )
        if not run_id:
            return {"success": False, "error": "Could not persist run (DB unavailable)"}

        job = build_start_job(
            run_id=run_id,
            run_kind=COMPOSE_RUN_KIND,
            request={
                # A reference, not a path: the agent layer asks for the resolved
                # layers at run start, so an edited definition reaches the next run.
                "arch": "",
                "playbook": f"{WORKFLOW_SCHEME}{workflow.id}",
                "config": "",
                "prompt": self._build_target_context(parameters),
            },
            enqueued_by=triggered_by or "api",
        )
        try:
            job_id = await enqueue_run(job)
        except Exception as exc:  # noqa: BLE001
            run_service.finalize_run(
                run_id, status="failed", error=f"Could not enqueue run: {exc}"
            )
            logger.error("Could not enqueue workflow run %s: %s", run_id, exc)
            return {
                "success": False,
                "error": "run queue unavailable",
                "run_id": run_id,
            }

        return {
            "success": True,
            "status": "queued",
            "run_id": run_id,
            "job_id": job_id,
            "workflow": workflow_dict,
            "parameters": parameters,
            "executed_at": datetime.now().isoformat(),
        }

    def _build_target_context(self, parameters: Dict[str, Any]) -> str:
        """Build a context string from execution parameters."""
        parts = []

        finding_id = parameters.get("finding_id")
        case_id = parameters.get("case_id")
        context = parameters.get("context", "")
        hypothesis = parameters.get("hypothesis", "")

        if finding_id:
            try:
                from core.storage.database_data_service import \
                    DatabaseDataService

                data_service = DatabaseDataService()
                finding = data_service.get_finding(finding_id)
                if finding:
                    techniques = finding.get("predicted_techniques", [])
                    technique_str = (
                        ", ".join([t.get("technique_id", "") for t in techniques])
                        if techniques
                        else "None"
                    )
                    parts.append(f"""**Target Finding:**
- Finding ID: {finding.get('finding_id')}
- Severity: {finding.get('severity')}
- Data Source: {finding.get('data_source')}
- Timestamp: {finding.get('timestamp')}
- Anomaly Score: {finding.get('anomaly_score', 'N/A')}
- Description: {finding.get('description', 'N/A')}
- MITRE ATT&CK Techniques: {technique_str}""")
                else:
                    parts.append(
                        f"**Target Finding ID:** {finding_id} (details will be retrieved during execution)"
                    )
            except Exception:
                parts.append(
                    f"**Target Finding ID:** {finding_id} (use get_finding to retrieve details)"
                )

        if case_id:
            try:
                from core.storage.database_data_service import \
                    DatabaseDataService

                data_service = DatabaseDataService()
                case = data_service.get_case(case_id)
                if case:
                    parts.append(f"""**Target Case:**
- Case ID: {case.get('case_id')}
- Title: {case.get('title')}
- Status: {case.get('status')}
- Priority: {case.get('priority')}
- Description: {case.get('description', 'N/A')}
- Finding Count: {len(case.get('finding_ids', []))}""")
                else:
                    parts.append(
                        f"**Target Case ID:** {case_id} (details will be retrieved during execution)"
                    )
            except Exception:
                parts.append(
                    f"**Target Case ID:** {case_id} (use get_case to retrieve details)"
                )

        if hypothesis:
            parts.append(f"**Hunt Hypothesis:** {hypothesis}")

        if context:
            parts.append(f"**Additional Context:** {context}")

        if not parts:
            parts.append(
                "No specific target provided. Use available tools to identify relevant findings and cases."
            )

        return "\n\n".join(parts)


# Singleton instance
_workflows_service: Optional[WorkflowsService] = None


def get_workflows_service() -> WorkflowsService:
    """Get singleton WorkflowsService instance."""
    global _workflows_service
    if _workflows_service is None:
        _workflows_service = WorkflowsService()
    return _workflows_service
