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
# The hypothesis loop, not a phase chain: the lead decides what to test next from
# what the evidence has done to each belief, and a phase order cannot express that.
run_kind: hunt

# What this hunt is out to test. Stated here rather than inferred from a prompt,
# so the run's premise is something a person wrote and review can see.
hypotheses:
  - "A host is beaconing to attacker-controlled infrastructure on a regular interval"
  - "Credentials taken from that host have been reused elsewhere in the estate"
attack_techniques:
  - T1071.001
  - T1078
data_domains:
  - network
  - authentication
  - endpoint

objectives:
  - "State a hypothesis and the scope that would test it"
  - "Characterise the network and artifact evidence bearing on it"
  - "Enrich every observable and attribute where the evidence supports it"
  - "Report the hypothesis as confirmed, refuted or inconclusive, with reasons"
# The roster, not an order: the lead dispatches whichever of these the question in
# front of it needs. Their prompts and tool grants live in arch/threathunt.yaml,
# so what stands here is who can be asked and what each is for.
phases:
  - id: threat_hunter
    agent: threat_hunter
    name: "Behavioural hunting"
    tools: [search_findings, nearest_neighbors, telemetry_search]
    instructions: |
      Broad behavioural hunting across the signal detection already scored and the
      telemetry behind it. "Nothing matched" is a finding about visibility, not a
      failure: say which sources you queried and which you could not.

  - id: network_analyst
    agent: network_analyst
    name: "Traffic shape"
    tools: [telemetry_search, search_findings]
    instructions: |
      Beaconing intervals, jitter, volume asymmetry, DNS and HTTP. Quantify: a
      regular interval with low variance is the signal, a busy host is not.

  - id: threat_intel
    agent: threat_intel
    name: "Observable enrichment"
    tools: [lookup_indicators]
    instructions: |
      Reputation and attribution for observables, against the indicator database
      and whatever intel integrations are connected. A miss is not exoneration:
      say "not in the feed" and never report an unknown observable as benign.
---

# Threat Hunt Workflow

Proactive, hypothesis-driven threat hunting. This text is the hunt's narrative — the Hunt Lead reads it as standing context for every decision it makes.

A hunt does not walk a sequence of steps. It puts the hypotheses above on the board, and each iteration the Hunt Lead reads a digest of what has been gathered so far and chooses what to do next: dispatch a worker against an open question, expand a piece of evidence it was shown, pivot onto an entity, deepen a line that is paying off, abandon one that is not, validate a hypothesis it believes is settled, stop and ask for an operator, or conclude. What the evidence did to each belief is what drives the next move, which is why there is no phase order to state.

Every hypothesis ends as proven, disproven or inconclusive. Inconclusive is a legitimate ending and must be reported as itself: distinguish "we looked and it was not there" from "we could not look" — they read identically in a report that does not separate them, and only one of them clears the hypothesis.

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

The run's own ledger, and a hunt report rendered from it. The console reads the
standing of each hypothesis while the hunt is in flight:

```json
{
  "status": "terminal",
  "iteration": 7,
  "evidence_count": 34,
  "hypotheses": [
    {
      "statement": "A host is beaconing to attacker-controlled infrastructure on a regular interval",
      "status": "proven",
      "attack_technique": "T1071.001",
      "resolution_reason": "300s interval, variance under 4s, across 19 hours to 185.220.101.1"
    },
    {
      "statement": "Credentials taken from that host have been reused elsewhere in the estate",
      "status": "inconclusive",
      "attack_technique": "T1078",
      "resolution_reason": "authentication telemetry retained for 7 days; the beaconing predates it"
    }
  ]
}
```
