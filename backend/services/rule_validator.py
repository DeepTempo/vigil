class RuleValidator:
    """
    Validator for Sigma detection rules.
    Ensures generated output conforms to the Sigma specification 
    before downstream formatting or persistence.
    """

    def validate_sigma(self, rule: dict) -> bool:
        """Simple boolean check for legacy support."""
        is_valid, _ = self.validate_sigma_detailed(rule)
        return is_valid

    def validate_sigma_detailed(self, rule: dict) -> tuple[bool, str]:
        """
        Performs strict schema validation.
        Returns (is_valid, error_message).
        """
        required = ["title", "logsource", "detection"]
        
        if not rule:
            return False, "Empty rule received"

        for key in required:
            if key not in rule:
                return False, f"Missing required field: {key}"

        # Sub-validation for logsource
        logsource = rule.get("logsource", {})
        if not isinstance(logsource, dict):
            return False, "logsource must be an object"
        
        # Sub-validation for detection
        detection = rule.get("detection", {})
        if "selection" not in detection and "condition" not in detection:
            return False, "detection must contain selection or condition"

        return True, ""
