from services.ai_service import AIService
from services.rule_validator import RuleValidator
from services.rule_formatter import RuleFormatter
from services.coverage_service import CoverageService
from services.deployment_service import DeploymentService
from db.detection_library import DetectionLibrary

class DetectionRuleGeneratorAgent:
    def __init__(self):
        self.ai = AIService()
        self.validator = RuleValidator()
        self.formatter = RuleFormatter()
        self.coverage = CoverageService()
        self.db = DetectionLibrary()
        self.deployer = DeploymentService()

    def enrich_logsource(self, rule, finding):
        source = finding.get("source", "")

        if source == "windows":
            rule["logsource"] = {"product": "windows"}
        elif source == "linux":
            rule["logsource"] = {"product": "linux"}
        elif source == "network":
            rule["logsource"] = {"product": "network"}

    def run(self, finding, technique_id, target="sigma", deploy=False):
        """
        finding: dict (observed attack)
        technique_id: str (MITRE ATT&CK ID)
        target: sigma | splunk | elastic
        """

        # 1. Generate Sigma (base format)
        sigma_rule = self.ai.generate_sigma_rule(finding, technique_id)

        if not sigma_rule:
            raise Exception("AI failed to generate rule")

        self.enrich_logsource(sigma_rule, finding)

        if not self.validator.validate_sigma(sigma_rule):
            raise Exception("Invalid Sigma rule generated")

        # 2. Add metadata
        sigma_rule["tags"] = [f"attack.{technique_id}"]
        sigma_rule["source"] = "auto-generated"
        sigma_rule["severity"] = finding.get("severity", "medium")

        # 3. Add false positives
        sigma_rule["falsepositives"] = self.ai.generate_false_positives(finding)

        # 4. Convert format if needed
        formatted_rule = self.formatter.convert(sigma_rule, target)

        # 5. Store in detection library
        self.db.save_rule(sigma_rule, technique_id)

        # 6. Update coverage
        self.coverage.mark_covered(technique_id)

        # 7. Optional deployment (with approval)
        if deploy:
            approved = self.deployer.request_approval(sigma_rule)
            if approved:
                self.deployer.deploy(formatted_rule, target)

        return {
            "sigma": sigma_rule,
            "formatted": formatted_rule
        }
