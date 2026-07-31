"""Shim — moved to core.skills.skill_service. Remove in R8 (#489)."""

from core.skills.skill_service import MITRE_TACTICS, SkillService

__all__ = ["MITRE_TACTICS", "SkillService"]
