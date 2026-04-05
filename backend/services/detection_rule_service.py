import logging
import json
import hashlib
from datetime import datetime
from typing import Optional, List, Dict, Any

from database.models import DetectionRule
from database.connection import get_db_manager
from services.llm_gateway import get_llm_gateway
from backend.services.rule_formatter import RuleFormatter
from backend.services.rule_validator import RuleValidator

logger = logging.getLogger(__name__)

class DetectionEngineeringEngine:
    """
    Institutional-grade Detection Engineering Engine.
    Automates the generation, validation, and lifecycle management of detection rules.
    """
    
    def __init__(self):
        self.llm = get_llm_gateway()
        self.formatter = RuleFormatter()
        self.validator = RuleValidator()

    def sanitize_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Hardens inputs against prompt injection by whitelisting fields.
        """
        whitelisted_keys = ["finding_id", "data_source", "description", "mitre_predictions"]
        sanitized = {k: finding.get(k) for k in whitelisted_keys if k in finding}
        
        # Truncate description to prevent long-input injection attacks
        if "description" in sanitized and sanitized["description"]:
            sanitized["description"] = sanitized["description"][:1000]
            
        return sanitized

    async def generate_rule(self, finding: Dict[str, Any]) -> Optional[DetectionRule]:
        """
        Orchestrates the detection engineering pipeline.
        Includes hardened sanitization, LLM-based logic generation, and rigorous validation.
        """
        finding_id = finding.get('finding_id', 'unknown')
        logger.info(f"[DET_ENG_ENGINE_START] Initiating rule engineering for finding: {finding_id}")
        
        try:
            # 1. Hardened Input
            clean_finding = self.sanitize_finding(finding)
            technique_id = clean_finding.get("mitre_predictions", {}).get("technique_id", "T1059")

            # 2. Secure Prompt Construction (Hybrid Insights)
            prompt = f"""Generate a high-fidelity Sigma detection rule for the following finding.
            Focus on the technique: {technique_id}
            Finding Data: {json.dumps(clean_finding)}
            
            CONTRACT: You MUST return ONLY a valid JSON object. No markdown, no prose.
            GUIDANCE: Ensure detection logic minimizes false positives and is specific to the observed behavior.
            
            FIELDS:
            - title (string)
            - description (string)
            - logsource (object with category/product)
            - detection (object with selection/condition)
            - falsepositives (list of strings)
            - level (string: 'low', 'medium', 'high', 'critical')
            - tags (list containing "attack." + technique_id)
            - confidence_reasoning (string: short explanation of why this logic is effective)
            """

            # 3. Request via Job Queue
            logger.info(f"[DET_ENG_ENGINE_LLM_REQUEST] Submitting to LLM Gateway for finding {finding_id}")
            response = await self.llm.submit_insights(
                content=prompt,
                priority="medium"
            )

            if not response or not response.get("content"):
                logger.error(f"[DET_ENG_ENGINE_LLM_FAILURE] Empty response for finding {finding_id}")
                return None

            # 4. Parse & Strict Schema Validation
            raw_rule = self._extract_json(response.get("content", ""))
            
            # Validation Checkpoint
            is_valid, validation_error = self.validator.validate_sigma_detailed(raw_rule)
            if not is_valid:
                logger.error(f"[DET_ENG_ENGINE_VALIDATION_FAILURE] {validation_error} for finding {finding_id}")
                return None

            # 5. Idempotency Check
            rule_hash = self._generate_rule_hash(technique_id, raw_rule)
            with get_db_manager().session_scope() as session:
                existing = session.query(DetectionRule).filter(DetectionRule.rule_hash == rule_hash).first()
                if existing:
                    logger.info(f"[DET_ENG_ENGINE_DUPLICATE] Rule already exists for {technique_id}: id={existing.id}")
                    return existing

            # 6. Formatter Layer
            spl = self.formatter.sigma_to_spl(raw_rule)
            kql = self.formatter.sigma_to_kql(raw_rule)

            # 7. Hybrid Confidence Scoring (Staff-Level Refinement)
            confidence_score = self._calculate_hybrid_confidence(raw_rule, clean_finding)
            confidence_reasoning = raw_rule.get("confidence_reasoning", "Generated based on attack telemetry.")
            
            # 8. Persistence
            with get_db_manager().session_scope() as session:
                rule = DetectionRule(
                    technique_id=technique_id,
                    sigma_rule=raw_rule,
                    spl_query=spl,
                    kql_query=kql,
                    rule_hash=rule_hash,
                    confidence=confidence_score,
                    confidence_reasoning=confidence_reasoning,
                    source="auto-generated"
                )
                session.add(rule)
                session.flush()
                session.refresh(rule)
                
                # 9. Coverage Hook
                self._update_coverage_metadata(technique_id)
                
                logger.info(f"[DET_ENG_ENGINE_SUCCESS] Persisted rule {rule.id} [confidence={confidence_score}] for {technique_id}")
                return rule

        except Exception as e:
            logger.error(f"[DET_ENG_ENGINE_ERROR] Unexpected failure for {finding_id}: {str(e)}")
            return None

    def _generate_rule_hash(self, technique_id: str, sigma_rule: Dict[str, Any]) -> str:
        """Generates a deterministic hash for deduplication."""
        # Use only relevant fields for hashing to avoid metadata-only changes triggering duplicates
        logic = {
            "logsource": sigma_rule.get("logsource"),
            "detection": sigma_rule.get("detection")
        }
        canonical = json.dumps(logic, sort_keys=True)
        raw = f"{technique_id}:{canonical}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def _calculate_hybrid_confidence(self, sigma_rule: Dict[str, Any], finding: Dict[str, Any]) -> int:
        """
        Hybrid scoring model combining internal telemetry and rule structure.
        """
        score = 0
        
        # 1. Structural Integrity (+30)
        logsource = sigma_rule.get("logsource", {})
        if logsource.get("category") or logsource.get("product"):
            score += 15
        if sigma_rule.get("detection", {}).get("selection"):
            score += 15
            
        # 2. Contextual Alignment (+20)
        source_type = finding.get("data_source", "").lower()
        rule_product = str(logsource.get("product", "")).lower()
        if source_type in rule_product or rule_product in source_type:
            score += 20
        elif source_type in ["edr", "sysmon", "windows"]: # Common high-fid sources
            score += 10
            
        # 3. Logic Complexity (+30)
        selection = sigma_rule.get("detection", {}).get("selection", {})
        if isinstance(selection, dict):
            # More fields usually means higher specificity/lower noise
            score += min(30, len(selection) * 10)
            
        # 4. Global Validation (+20)
        # Reaching this point means it passed RuleValidator.validate_sigma_detailed()
        score += 20
        
        return min(100, score)

    def _update_coverage_metadata(self, technique_id: str):
        """Asynchronous hook to signal coverage map update."""
        logger.info(f"[COVERAGE_UPDATE_PENDING] technique={technique_id}")

    def _extract_json(self, text: str) -> Dict[str, Any]:
        """Helper to extract JSON from LLM response."""
        try:
            if "```json" in text:
                return json.loads(text.split("```json")[1].split("```")[0])
            return json.loads(text or "{}")
        except Exception:
            return {}

# Institution-grade naming alias
DetectionRuleService = DetectionEngineeringEngine
