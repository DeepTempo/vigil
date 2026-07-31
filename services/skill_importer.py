"""Shim — moved to core.skills.skill_importer. Remove in R8 (#489)."""

from core.skills.skill_importer import (
    ALLOWED_CATEGORIES,
    MAX_ENTRIES,
    MAX_SKILL_MD_BYTES,
    MAX_ZIP_BYTES,
    SkillImportError,
    import_skill_zip,
)

__all__ = [
    "ALLOWED_CATEGORIES",
    "MAX_ENTRIES",
    "MAX_SKILL_MD_BYTES",
    "MAX_ZIP_BYTES",
    "SkillImportError",
    "import_skill_zip",
]
