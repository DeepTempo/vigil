rules_db = []

class DetectionLibrary:

    def save_rule(self, rule, technique_id):
        rules_db.append({
            "technique": technique_id,
            "rule": rule,
            "source": "auto-generated"
        })
