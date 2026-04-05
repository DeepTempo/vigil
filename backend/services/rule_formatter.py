import re

class RuleFormatter:
    """
    Production-grade formatter with injection protection.
    Responsible for converting Sigma AST to native query languages.
    """

    def sigma_to_spl(self, rule: dict) -> str:
        """Converts Sigma to SPL with sanitization."""
        selection = rule.get("detection", {}).get("selection", {})
        conditions = []
        
        for key, value in selection.items():
            # Sanitize values to prevent SPL injection (escaping quotes/pipes)
            clean_val = self.sanitize_value(str(value))
            conditions.append(f'{key}="{clean_val}"')

        return f'index=* ({" AND ".join(conditions)})'

    def sigma_to_kql(self, rule: dict) -> str:
        """Converts Sigma to KQL with sanitization."""
        selection = rule.get("detection", {}).get("selection", {})
        conditions = []
        
        for key, value in selection.items():
            clean_val = self.sanitize_value(str(value))
            conditions.append(f'{key} == "{clean_val}"')

        return f'DeviceEvents | where {" and ".join(conditions)}'

    def sanitize_value(self, value: str) -> str:
        """
        Escapes special query characters to prevent injection attacks.
        """
        if not value:
            return ""
        # 1. Escape double quotes
        value = value.replace('"', '\\"')
        # 2. Strip potential SPL pipe commands
        value = re.sub(r'\|\s*\w+', '', value)
        return value
