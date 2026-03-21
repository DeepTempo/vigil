"""Investigation workflow service for managing multi-phase investigations."""

import json
import logging
from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict, field
from enum import Enum

logger = logging.getLogger(__name__)


class InvestigationPhase(Enum):
    """Phases of an investigation workflow."""
    INITIALIZE = "initialize"
    GATHER_CONTEXT = "gather_context"
    ANALYZE = "analyze"
    CORRELATE = "correlate"
    REPORT = "report"
    CLOSED = "closed"


class PhaseStatus(Enum):
    """Status of an investigation phase."""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    SKIPPED = "skipped"


@dataclass
class PhaseResult:
    """Results from a completed phase."""
    phase: str  # InvestigationPhase value
    status: str  # PhaseStatus value
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    findings: List[str] = field(default_factory=list)
    notes: str = ""
    data: Dict = field(default_factory=dict)


@dataclass
class InvestigationWorkflow:
    """Represents an investigation workflow with multiple phases."""
    workflow_id: str
    case_id: str
    title: str
    description: str
    current_phase: str  # InvestigationPhase value
    status: str  # "active", "paused", "completed"
    created_at: str
    updated_at: str
    
    # Phase tracking
    phases: Dict[str, PhaseResult] = field(default_factory=dict)
    
    # Investigation context
    entities_discovered: Dict[str, List[str]] = field(default_factory=dict)
    queries_executed: List[Dict] = field(default_factory=list)
    hypotheses: List[Dict] = field(default_factory=list)
    
    # Metadata
    assigned_to: Optional[str] = None
    priority: str = "medium"


class InvestigationWorkflowService:
    """Service for managing investigation workflows."""
    
    def __init__(self, data_dir: Optional[Path] = None):
        """
        Initialize investigation workflow service.
        
        Args:
            data_dir: Directory for storing workflows (default: ./data)
        """
        if data_dir is None:
            data_dir = Path(__file__).parent.parent / "data"
        
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.workflows_file = self.data_dir / "investigation_workflows.json"
        
        # Create file if it doesn't exist
        if not self.workflows_file.exists():
            self._save_workflows([])
    
    def _load_workflows(self) -> List[InvestigationWorkflow]:
        """Load all workflows from file."""
        try:
            with open(self.workflows_file, 'r') as f:
                data = json.load(f)
                workflows = []
                for wf_data in data:
                    # Convert phases dict
                    if 'phases' in wf_data and wf_data['phases']:
                        phases = {}
                        for phase_name, phase_data in wf_data['phases'].items():
                            phases[phase_name] = PhaseResult(**phase_data)
                        wf_data['phases'] = phases
                    workflows.append(InvestigationWorkflow(**wf_data))
                return workflows
        except FileNotFoundError:
            return []
        except Exception as e:
            logger.error(f"Error loading workflows: {e}")
            return []
    
    def _save_workflows(self, workflows: List[InvestigationWorkflow]):
        """Save all workflows to file."""
        try:
            data = []
            for wf in workflows:
                wf_dict = asdict(wf)
                # Convert PhaseResult objects to dicts
                if 'phases' in wf_dict and wf_dict['phases']:
                    phases_dict = {}
                    for phase_name, phase_result in wf_dict['phases'].items():
                        if isinstance(phase_result, dict):
                            phases_dict[phase_name] = phase_result
                        else:
                            phases_dict[phase_name] = asdict(phase_result)
                    wf_dict['phases'] = phases_dict
                data.append(wf_dict)
            
            with open(self.workflows_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving workflows: {e}")
    
    def create_workflow(
        self,
        case_id: str,
        title: str,
        description: str,
        assigned_to: Optional[str] = None,
        priority: str = "medium"
    ) -> InvestigationWorkflow:
        """
        Create a new investigation workflow.
        
        Args:
            case_id: Associated case ID
            title: Workflow title
            description: Workflow description
            assigned_to: Analyst assigned
            priority: Priority level
        
        Returns:
            Created workflow
        """
        workflow = InvestigationWorkflow(
            workflow_id=f"wf-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}",
            case_id=case_id,
            title=title,
            description=description,
            current_phase=InvestigationPhase.INITIALIZE.value,
            status="active",
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat(),
            assigned_to=assigned_to,
            priority=priority
        )
        
        # Initialize all phases
        for phase in InvestigationPhase:
            if phase != InvestigationPhase.CLOSED:
                workflow.phases[phase.value] = PhaseResult(
                    phase=phase.value,
                    status=PhaseStatus.NOT_STARTED.value
                )
        
        # Mark first phase as in progress
        workflow.phases[InvestigationPhase.INITIALIZE.value].status = PhaseStatus.IN_PROGRESS.value
        workflow.phases[InvestigationPhase.INITIALIZE.value].started_at = datetime.now().isoformat()
        
        # Save
        workflows = self._load_workflows()
        workflows.append(workflow)
        self._save_workflows(workflows)
        
        logger.info(f"Created workflow {workflow.workflow_id} for case {case_id}")
        return workflow
    
    def get_workflow(self, workflow_id: str) -> Optional[InvestigationWorkflow]:
        """Get a specific workflow by ID."""
        workflows = self._load_workflows()
        for wf in workflows:
            if wf.workflow_id == workflow_id:
                return wf
        return None
    
    def get_workflow_by_case(self, case_id: str) -> Optional[InvestigationWorkflow]:
        """Get workflow associated with a case."""
        workflows = self._load_workflows()
        for wf in workflows:
            if wf.case_id == case_id and wf.status != "completed":
                return wf
        return None
    
    def list_workflows(
        self,
        status: Optional[str] = None,
        assigned_to: Optional[str] = None
    ) -> List[InvestigationWorkflow]:
        """List workflows with optional filters."""
        workflows = self._load_workflows()
        
        if status:
            workflows = [wf for wf in workflows if wf.status == status]
        if assigned_to:
            workflows = [wf for wf in workflows if wf.assigned_to == assigned_to]
        
        # Sort by updated_at descending
        workflows.sort(key=lambda x: x.updated_at, reverse=True)
        
        return workflows
    
    def advance_phase(
        self,
        workflow_id: str,
        notes: str = "",
        findings: Optional[List[str]] = None,
        data: Optional[Dict] = None
    ) -> Optional[InvestigationWorkflow]:
        """
        Advance workflow to the next phase.
        
        Args:
            workflow_id: Workflow ID
            notes: Notes for completed phase
            findings: Findings from completed phase
            data: Additional data from completed phase
        
        Returns:
            Updated workflow
        """
        workflows = self._load_workflows()
        
        for workflow in workflows:
            if workflow.workflow_id == workflow_id:
                # Get current phase
                current_phase_enum = InvestigationPhase(workflow.current_phase)
                current_phase_result = workflow.phases[workflow.current_phase]
                
                # Mark current phase as completed
                current_phase_result.status = PhaseStatus.COMPLETED.value
                current_phase_result.completed_at = datetime.now().isoformat()
                current_phase_result.notes = notes
                if findings:
                    current_phase_result.findings = findings
                if data:
                    current_phase_result.data = data
                
                # Determine next phase
                phase_order = [
                    InvestigationPhase.INITIALIZE,
                    InvestigationPhase.GATHER_CONTEXT,
                    InvestigationPhase.ANALYZE,
                    InvestigationPhase.CORRELATE,
                    InvestigationPhase.REPORT
                ]
                
                current_index = phase_order.index(current_phase_enum)
                
                if current_index < len(phase_order) - 1:
                    # Move to next phase
                    next_phase = phase_order[current_index + 1]
                    workflow.current_phase = next_phase.value
                    workflow.phases[next_phase.value].status = PhaseStatus.IN_PROGRESS.value
                    workflow.phases[next_phase.value].started_at = datetime.now().isoformat()
                else:
                    # Investigation complete
                    workflow.current_phase = InvestigationPhase.CLOSED.value
                    workflow.status = "completed"
                
                workflow.updated_at = datetime.now().isoformat()
                self._save_workflows(workflows)
                
                logger.info(f"Advanced workflow {workflow_id} to phase {workflow.current_phase}")
                return workflow
        
        logger.warning(f"Workflow {workflow_id} not found")
        return None
    
    def update_phase(
        self,
        workflow_id: str,
        phase: InvestigationPhase,
        notes: str = "",
        findings: Optional[List[str]] = None,
        data: Optional[Dict] = None
    ) -> Optional[InvestigationWorkflow]:
        """
        Update a specific phase without advancing.
        
        Args:
            workflow_id: Workflow ID
            phase: Phase to update
            notes: Notes to add
            findings: Findings to add
            data: Data to add
        
        Returns:
            Updated workflow
        """
        workflows = self._load_workflows()
        
        for workflow in workflows:
            if workflow.workflow_id == workflow_id:
                phase_result = workflow.phases.get(phase.value)
                if not phase_result:
                    logger.warning(f"Phase {phase.value} not found in workflow {workflow_id}")
                    return None
                
                if notes:
                    phase_result.notes = notes
                if findings:
                    phase_result.findings.extend(findings)
                if data:
                    phase_result.data.update(data)
                
                workflow.updated_at = datetime.now().isoformat()
                self._save_workflows(workflows)
                
                logger.info(f"Updated phase {phase.value} in workflow {workflow_id}")
                return workflow
        
        logger.warning(f"Workflow {workflow_id} not found")
        return None
    
    def add_entity(
        self,
        workflow_id: str,
        entity_type: str,
        entity_value: str
    ) -> Optional[InvestigationWorkflow]:
        """Add a discovered entity to the workflow context."""
        workflows = self._load_workflows()
        
        for workflow in workflows:
            if workflow.workflow_id == workflow_id:
                if entity_type not in workflow.entities_discovered:
                    workflow.entities_discovered[entity_type] = []
                
                if entity_value not in workflow.entities_discovered[entity_type]:
                    workflow.entities_discovered[entity_type].append(entity_value)
                
                workflow.updated_at = datetime.now().isoformat()
                self._save_workflows(workflows)
                
                logger.info(f"Added entity {entity_type}:{entity_value} to workflow {workflow_id}")
                return workflow
        
        return None
    
    def add_query(
        self,
        workflow_id: str,
        query_type: str,
        query: str,
        results_count: int = 0
    ) -> Optional[InvestigationWorkflow]:
        """Add an executed query to the workflow context."""
        workflows = self._load_workflows()
        
        for workflow in workflows:
            if workflow.workflow_id == workflow_id:
                workflow.queries_executed.append({
                    "timestamp": datetime.now().isoformat(),
                    "type": query_type,
                    "query": query,
                    "results_count": results_count
                })
                
                workflow.updated_at = datetime.now().isoformat()
                self._save_workflows(workflows)
                
                logger.info(f"Added query to workflow {workflow_id}")
                return workflow
        
        return None
    
    def add_hypothesis(
        self,
        workflow_id: str,
        hypothesis: str,
        confidence: float,
        evidence: List[str]
    ) -> Optional[InvestigationWorkflow]:
        """Add an investigation hypothesis."""
        workflows = self._load_workflows()
        
        for workflow in workflows:
            if workflow.workflow_id == workflow_id:
                workflow.hypotheses.append({
                    "timestamp": datetime.now().isoformat(),
                    "hypothesis": hypothesis,
                    "confidence": confidence,
                    "evidence": evidence,
                    "status": "active"
                })
                
                workflow.updated_at = datetime.now().isoformat()
                self._save_workflows(workflows)
                
                logger.info(f"Added hypothesis to workflow {workflow_id}")
                return workflow
        
        return None
    
    def get_stats(self) -> Dict:
        """Get workflow statistics."""
        workflows = self._load_workflows()
        
        return {
            "total": len(workflows),
            "active": len([wf for wf in workflows if wf.status == "active"]),
            "paused": len([wf for wf in workflows if wf.status == "paused"]),
            "completed": len([wf for wf in workflows if wf.status == "completed"]),
            "by_phase": self._count_by_phase(workflows)
        }
    
    def _count_by_phase(self, workflows: List[InvestigationWorkflow]) -> Dict[str, int]:
        """Count workflows by current phase."""
        counts = {}
        for workflow in workflows:
            if workflow.status == "active":
                phase = workflow.current_phase
                counts[phase] = counts.get(phase, 0) + 1
        return counts


# Singleton instance
_workflow_service: Optional[InvestigationWorkflowService] = None


def get_workflow_service() -> InvestigationWorkflowService:
    """Get singleton InvestigationWorkflowService instance."""
    global _workflow_service
    if _workflow_service is None:
        _workflow_service = InvestigationWorkflowService()
    return _workflow_service

