import json
import openai

class AIService:

    def generate_sigma_rule(self, finding, technique_id):
        prompt = f"""
You are a detection engineer.

Generate a Sigma rule in JSON.

Technique: {technique_id}
Finding: {json.dumps(finding)}

Include:
- title
- description
- logsource
- detection
- level

Output ONLY JSON.
"""

        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2
        )

        return self.safe_parse(response["choices"][0]["message"]["content"])

    def generate_false_positives(self, finding):
        if finding.get("type") == "rdp_lateral_movement":
            return [
                "Legitimate RDP by IT admins",
                "Remote support tools"
            ]
        return ["Legitimate activity"]

    def safe_parse(self, text):
        try:
            return json.loads(text)
        except:
            return None
