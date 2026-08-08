"""Pydantic ORM-mode schemas for the models in ``database.models``.

Each model's serialized shape is declared here once, replacing the
hand-written ``to_dict()`` methods that previously defined it implicitly.
"""

from database.schemas.ai import (
    AIDecisionLogSchema,
    AIModelConfigSchema,
    ChatMessageSchema,
    ConversationSchema,
    ConversationSummarySchema,
    LLMInteractionLogSchema,
    LLMProviderConfigSchema,
)
from database.schemas.auth import (
    RoleSchema,
    UserSchema,
)
from database.schemas.base import ORMSchema
from database.schemas.case import (
    CaseBaseSchema,
    CaseSchema,
    CaseWithFindingsSchema,
)
from database.schemas.case_entities import (
    CaseAttachmentSchema,
    CaseAuditLogSchema,
    CaseClosureInfoSchema,
    CaseCommentSchema,
    CaseEscalationSchema,
    CaseEvidenceSchema,
    CaseIOCSchema,
    CaseMetricsSchema,
    CaseNotificationSchema,
    CaseRelationshipSchema,
    CaseSLASchema,
    CaseTaskSchema,
    CaseTemplateSchema,
    CaseWatcherSchema,
    SLAPolicySchema,
)
from database.schemas.config import (
    AttackLayerSchema,
    ConfigAuditLogSchema,
    FederationSourceSchema,
    IntegrationConfigSchema,
    SharedIOCSchema,
    SketchMappingSchema,
    SystemConfigSchema,
    ThreatIndicatorSchema,
    UserPreferenceSchema,
)
from database.schemas.finding import FindingSchema
from database.schemas.workflow import (
    ApprovalActionSchema,
    CustomAgentSchema,
    CustomWorkflowSchema,
    InvestigationLogSchema,
    InvestigationSchema,
    SkillSchema,
    WorkflowRunPhaseSchema,
    WorkflowRunSchema,
)

__all__ = [
    "AIDecisionLogSchema",
    "AIModelConfigSchema",
    "ApprovalActionSchema",
    "AttackLayerSchema",
    "CaseAttachmentSchema",
    "CaseAuditLogSchema",
    "CaseBaseSchema",
    "CaseClosureInfoSchema",
    "CaseCommentSchema",
    "CaseEscalationSchema",
    "CaseEvidenceSchema",
    "CaseIOCSchema",
    "CaseMetricsSchema",
    "CaseNotificationSchema",
    "CaseRelationshipSchema",
    "CaseSLASchema",
    "CaseSchema",
    "CaseTaskSchema",
    "CaseTemplateSchema",
    "CaseWatcherSchema",
    "CaseWithFindingsSchema",
    "ChatMessageSchema",
    "ConfigAuditLogSchema",
    "ConversationSchema",
    "ConversationSummarySchema",
    "CustomAgentSchema",
    "CustomWorkflowSchema",
    "FederationSourceSchema",
    "FindingSchema",
    "IntegrationConfigSchema",
    "InvestigationLogSchema",
    "InvestigationSchema",
    "LLMInteractionLogSchema",
    "LLMProviderConfigSchema",
    "ORMSchema",
    "RoleSchema",
    "SLAPolicySchema",
    "SharedIOCSchema",
    "SketchMappingSchema",
    "SkillSchema",
    "SystemConfigSchema",
    "ThreatIndicatorSchema",
    "UserPreferenceSchema",
    "UserSchema",
    "WorkflowRunPhaseSchema",
    "WorkflowRunSchema",
]
