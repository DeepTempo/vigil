import logging
from typing import Dict, Any
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from backend.services.detection_rule_service import DetectionRuleService

logger = logging.getLogger(__name__)

router = APIRouter()

class GenerateRuleRequest(BaseModel):
    """Request to generate a detection rule from a finding."""
    finding: Dict[str, Any]

@router.post("/generate-rule")
async def generate_rule(request: GenerateRuleRequest):
    """
    Generate a detection rule (Sigma, SPL, KQL) from a security finding.
    Utilizes AI to map indicators to technical detection queries.
    """
    service = DetectionRuleService()
    try:
        rule = await service.generate_rule(request.finding)
        
        if not rule:
            raise HTTPException(
                status_code=500, 
                detail="Failed to generate rule. Validation or LLM error."
            )
            
        return {
            "success": True,
            "rule": rule.to_dict()
        }
    except Exception as e:
        logger.error(f"API Error in generate-rule: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
