class RuleValidator:

    def validate_sigma(self, rule):
        required = ["title", "logsource", "detection"]

        if not rule:
            return False

        for key in required:
            if key not in rule:
                return False

        return True
