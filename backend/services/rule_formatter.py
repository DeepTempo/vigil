class RuleFormatter:

    def convert(self, sigma_rule, target):

        if target == "sigma":
            return sigma_rule

        if target == "splunk":
            return self.to_splunk(sigma_rule)

        if target == "elastic":
            return self.to_kql(sigma_rule)

        return sigma_rule

    def to_splunk(self, rule):
        # NOTE: Basic SPL/KQL conversion — can be extended with full field mappings
        selection = rule.get("detection", {}).get("selection", {})
        conditions = []

        for key, value in selection.items():
            conditions.append(f"{key}={value}")

        return "index=* " + " AND ".join(conditions)

    def to_kql(self, rule):
        return f"{rule['detection']}"
