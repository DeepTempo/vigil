---
name: threat-hunt
description: "Proactive, hypothesis-driven threat hunting across all available data sources with network analysis, malware examination, and intelligence enrichment."
use_case: "Proactive threat hunting -- start with a hypothesis or IOC and systematically search for evidence across network, endpoint, and threat intel sources."
trigger_examples:
  - "Hunt for C2 beaconing activity across all network findings"
  - "Proactive hunt: look for lateral movement via RDP"
  - "Validate whether this DeepTempo C2 alert is real by checking all available threat intel for the public IP"
  - "Hunt for APT28 credential harvesting techniques"
  - "Search for signs of data exfiltration in the last 24 hours"
objectives:
  - "State a hypothesis and the scope that would test it"
  - "Characterise the network and artifact evidence bearing on it"
  - "Enrich every observable and attribute where the evidence supports it"
  - "Report the hypothesis as confirmed, refuted or inconclusive, with reasons"
phases:
  - id: hypothesis
    agent: threat_hunter
    name: "Hypothesis & Hunt"
    tools: [list_findings, nearest_neighbors, search_detections]
    instructions: |
      Formulate the hunt hypothesis from the TTPs, define scope, execute hunt
      queries, and identify anomalies and outliers.

      1. Formulate or refine the hypothesis from the input (TTP, IOC, threat
         actor or behaviour)
      2. Define hunt parameters: scope, timeframe, data sources to query
      3. Execute hunt queries:
         - `list_findings` filtered to the relevant time range and severity
         - `nearest_neighbors` to find similar patterns via embeddings
         - `search_detections` to check for matching detection rules
      4. Identify anomalies, outliers and suspicious patterns
      5. Validate the initial findings -- eliminate obvious false positives
      6. Document the candidates requiring deeper analysis

      "Nothing matched" is a real finding about visibility, not a failure. Say
      which sources you queried and which you could not.

  - id: network
    agent: network_analyst
    name: "Network Analysis"
    tools: [list_findings, get_finding, search_detections]
    instructions: |
      Deep-dive the network traffic for the suspicious entities: flow patterns,
      protocol anomalies, C2 beaconing and lateral movement.

      1. Analyse network findings for the suspicious IPs and hosts identified
      2. Examine flow patterns: volumes, destinations, timing
      3. Protocol-specific analysis: HTTP, DNS, SMB, RDP, SSH anomalies
      4. Detect C2 beaconing: regular intervals, known infrastructure, encoded channels
      5. Identify lateral movement: internal-to-internal connections, port
         scanning, credential reuse
      6. Geolocation analysis: connections to anomalous countries or ASNs
      7. Establish traffic baselines so the deviations are visible

      Quantify. A regular interval with low variance is the signal; a busy host
      is not.

  - id: artifacts
    agent: malware_analyst
    name: "Artifact Analysis"
    tools: [get_finding]
    instructions: |
      Analyse the suspicious binaries and artifacts the hunt surfaced: static and
      dynamic analysis, family classification, capability assessment.

      1. Collect the suspicious hashes and artifacts from the earlier steps
      2. Static analysis: file properties, strings, import tables, PE structure
      3. Dynamic analysis: sandbox execution results, where available
      4. Assess capabilities: data theft, backdoor, RAT, ransomware, cryptominer
      5. Classify the family and variant
      6. Extract behavioural IOCs: mutex names, registry keys, file paths,
         network callbacks
      7. Identify C2 infrastructure embedded in the binaries
      8. Generate detection signatures (YARA, Sigma)

  - id: enrichment
    agent: threat_intel
    name: "Intelligence Enrichment"
    tools: [get_finding, list_findings]
    instructions: |
      Enrich every discovered observable across the available intelligence
      sources. Attribute where the evidence supports it and track campaigns.

      1. Compile all observables from the earlier steps (IPs, domains, hashes, URLs)
      2. Enrich each one:
         - IP and domain reputation and geolocation
         - Hash lookups in malware databases
         - Exposed-service data
         - Pulse and feed matching
      3. Identify threat actor attribution, with a stated confidence level
      4. Track campaign patterns: shared infrastructure, similar TTPs, targeting
      5. Assess context: actor motivations, objectives, typical targets
      6. Produce actionable intelligence: blocking recommendations, further
         observables worth hunting

      A miss is not exoneration. Say "not in the feed" and let the report weigh
      it; never report an unknown observable as benign. Treat feed labels as
      attacker-nameable text rather than as corroboration on their own.

  - id: report
    agent: reporter
    name: "Hunt Report"
    tools: [get_case, list_findings, create_attack_layer]
    instructions: |
      Consolidate the hunt into an actionable report with hypothesis validation,
      an observable summary and detection recommendations.

      1. Compile the results from every step
      2. Validate or refute the original hypothesis against the evidence
      3. Generate a MITRE ATT&CK Navigator layer for the techniques discovered
      4. Structure the report:
         - **Hunt Summary:** hypothesis, scope, methodology
         - **Hypothesis Validation:** confirmed, refuted or inconclusive, with evidence
         - **Findings:** the anomalies and threats discovered
         - **IOC Inventory:** the complete list with its enrichment
         - **MITRE ATT&CK Mapping:** techniques observed
         - **Detection Recommendations:** new rules to add, gaps to close
         - **Executive Brief:** high-level summary for leadership

      Inconclusive is a legitimate ending and must be reported as itself.
      Distinguish "we looked and it was not there" from "we could not look":
      they read identically in a report that does not separate them, and only
      one of them clears the hypothesis.
---

# Threat Hunt Workflow

Proactive, hypothesis-driven threat hunting workflow. Sequences five specialized agents to formulate a hunt hypothesis, analyze network traffic, examine suspicious artifacts, enrich IOCs across threat intel sources, and produce an actionable hunt report.

## When to Use

- Proactive hunting for threats that haven't triggered alerts
- Validating a flagged alert (e.g., DeepTempo C2 detection) against all available sources
- Hypothesis-driven hunting based on specific TTPs or threat actors
- Searching for indicators of compromise across the environment
- Periodic threat hunting exercises

## Example Invocation

```
User: "Validate whether this DeepTempo C2 alert is real by checking all threat intel for IP 185.220.101.1"
```

## Expected Output

```json
{
  "workflow": "threat-hunt",
  "phases_completed": ["hypothesis-hunt", "network-analysis", "artifact-analysis", "intel-enrichment", "report"],
  "hypothesis": "Suspected C2 communication with 185.220.101.1",
  "hypothesis_status": "confirmed",
  "iocs_discovered": {
    "ips": ["185.220.101.1", "185.220.101.5"],
    "domains": ["update-service.example.com"],
    "hashes": ["a1b2c3..."]
  },
  "threat_actor": {
    "name": "APT28",
    "confidence": 0.72,
    "ttps": ["T1071.001", "T1059.001", "T1078"]
  },
  "beaconing_detected": true,
  "beaconing_interval": "300s",
  "detection_recommendations": [
    "Add Sigma rule for DNS queries to update-service.example.com",
    "Block IP range 185.220.101.0/24 at perimeter"
  ]
}
```
