coverage_map = {}

class CoverageService:

    def mark_covered(self, technique_id):
        coverage_map[technique_id] = {
            "covered": True,
            "source": "auto-generated"
        }
