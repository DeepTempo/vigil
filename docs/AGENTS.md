# SOC AI Agents

13 specialized AI agents for different security operations tasks.

## Tool Access

All agents have access to tools through two integration methods:

### Agent SDK (Recommended - Web UI)
- **19 Backend Tools** via Claude API function calling
- Security detections, case management, approvals, MITRE ATT&CK
- **Zero desktop dependency** - Works entirely through the API
- Production-ready for multi-user deployments
- Enabled by default in web UI

### MCP Tools (Optional - Advanced Use)
- **100+ Extended Tools** for specialized integrations
- Requires additional MCP server configuration
- Best for advanced local workflows or specialized integrations

> **Default Behavior**: Agents automatically use backend tools via Agent SDK in the web UI with no additional configuration needed.

## Quick Reference

| Agent | Speed | Thinking | Use When |
|-------|-------|----------|----------|
| Triage | Fast | No | Prioritizing alert queue |
| Investigator | Thorough | Yes | Deep-dive analysis |
| Threat Hunter | Balanced | Yes | Proactive threat hunting |
| Correlator | Balanced | Yes | Linking related alerts |
| Responder | Fast | No | Immediate action items |
| Reporter | Balanced | No | Documentation, reports |
| MITRE Analyst | Balanced | Yes | ATT&CK technique mapping |
| Forensics | Thorough | Yes | Artifact analysis |
| Threat Intel | Balanced | Yes | IOC enrichment |
| Compliance | Balanced | No | Policy/regulation checks |
| Malware Analyst | Thorough | Yes | Malware analysis |
| Network Analyst | Balanced | Yes | Traffic analysis |
| Auto-Responder | Balanced | Yes | Autonomous actions |

## Skills (Workflows)

These workflows are formalized as **Skills** -- executable multi-agent playbooks in the [`/skills/`](/skills/) directory. Each skill has a `SKILL.md` file with YAML frontmatter metadata and detailed phase-by-phase instructions.

Skills can be executed from the **Skills** page in the UI or via the `/api/skills/{id}/execute` API endpoint.

| Skill | Agents | Use Case | Skill File |
|-------|--------|----------|------------|
| **Incident Response** | Triage -> Investigator -> Responder -> Reporter | Active incident handling | [`skills/incident-response/SKILL.md`](/skills/incident-response/SKILL.md) |
| **Full Investigation** | Investigator -> MITRE Analyst -> Correlator -> Responder -> Reporter | Deep-dive analysis with ATT&CK mapping | [`skills/full-investigation/SKILL.md`](/skills/full-investigation/SKILL.md) |
| **Threat Hunt** | Threat Hunter -> Network Analyst -> Malware Analyst -> Threat Intel -> Reporter | Proactive hypothesis-driven hunting | [`skills/threat-hunt/SKILL.md`](/skills/threat-hunt/SKILL.md) |
| **Forensic Analysis** | Forensics -> Malware Analyst -> Network Analyst -> Reporter | Post-incident forensics with chain of custody | [`skills/forensic-analysis/SKILL.md`](/skills/forensic-analysis/SKILL.md) |

### Adding Custom Skills

Create a new directory under `skills/` with a `SKILL.md` file:

```
skills/
  my-custom-workflow/
    SKILL.md    # YAML frontmatter + markdown workflow definition
```

The backend discovers skills automatically on startup. Use `POST /api/skills/reload` to pick up changes without restart.

## Agent Capabilities

### Triage Agent
- Rapid alert assessment
- Severity scoring
- False positive identification
- Escalation decisions

### Investigator Agent
- Root cause analysis
- Evidence collection
- Timeline reconstruction
- Cross-source correlation

### Threat Hunter Agent
- Hypothesis-driven hunting
- Anomaly detection
- Pattern recognition
- APT discovery
- **Pattern intelligence from 7,200+ detection rules**
- **Field usage learning and correlation**
- **Detection pattern extraction**

### Correlator Agent
- Multi-stage attack detection
- Campaign identification
- Entity relationship mapping
- Attack chain reconstruction

### Responder Agent
- Containment recommendations
- NIST IR framework
- Blast radius assessment
- Remediation steps

### Reporter Agent
- Executive summaries
- Technical reports
- Audience-tailored content
- Compliance documentation

### MITRE Analyst Agent
- Technique identification
- Kill chain analysis
- TTP mapping
- Framework contextualization
- Detection coverage analysis via `analyze_coverage` and `identify_gaps`
- Gap identification and prioritization

### Forensics Agent
- Artifact analysis
- Chain of custody
- Multi-domain forensics
- Evidence examination

### Threat Intel Agent
- IOC enrichment
- Actor attribution
- Campaign tracking
- OSINT integration

### Compliance Agent
- NIST, ISO, PCI-DSS, HIPAA, GDPR, SOC 2
- Policy validation
- Control assessment
- Audit preparation

### Malware Analyst Agent
- Static/dynamic analysis
- Family classification
- IOC extraction
- C2 identification

### Network Analyst Agent
- Flow analysis
- Protocol examination
- Lateral movement detection
- Exfiltration identification

### Auto-Responder Agent
- Confidence-based automation
- Approval workflow integration
- Autonomous containment
- Human oversight for low-confidence

## Approval Workflow Integration

All agents can submit actions to the approval queue:

| Confidence | Behavior |
|------------|----------|
| >= 0.90 | Auto-approved, executed |
| 0.85-0.89 | Auto-approved with flag |
| 0.70-0.84 | Requires manual approval |
| < 0.70 | Monitor only |

## Backend Tools by Agent (Agent SDK)

All 13 agents share access to the same 23 backend tools via Claude API function calling. Agents are differentiated by their system prompt, specialization, and reasoning style — not by having different tool access.

| Tool Category | Tools | Primary Users |
|---------------|-------|---------------|
| Findings | `list_findings`, `search_findings`, `get_findings_stats`, `get_finding`, `nearest_neighbors` | All agents |
| Cases | `list_cases`, `get_case`, `create_case`, `add_finding_to_case`, `update_case`, `add_resolution_step` | All agents |
| Detection Rules | `analyze_coverage`, `search_detections`, `identify_gaps`, `get_coverage_stats`, `get_detection_count` | Triage, Investigator, MITRE Analyst, Threat Hunter |
| ATT&CK | `get_attack_layer`, `get_technique_rollup` | MITRE Analyst, Reporter, Correlator |
| Approvals | `list_pending_approvals`, `get_approval_action`, `approve_action`, `reject_action`, `get_approval_stats` | Responder, Auto-Responder |

For extended integrations (Splunk, VirusTotal, Shodan, CrowdStrike, etc.), see [INTEGRATIONS.md](INTEGRATIONS.md).

See [DETECTION_ENGINEERING.md](DETECTION_ENGINEERING.md) for detection coverage workflows.

## Usage Tips

1. **Match agent to task** - Use the specialist for your need
2. **Switch freely** - Change agents mid-conversation
3. **Start with Triage** - When unsure where to begin
4. **End with Reporter** - Document findings
5. **Use thinking agents** - For complex analysis (Investigator, Hunter, Forensics)
6. **Use fast agents** - For quick decisions (Triage, Responder)
