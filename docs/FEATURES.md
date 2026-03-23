# Features

## Case Management

Full investigation lifecycle tracking.

### Case Tabs

| Tab | Purpose |
|-----|---------|
| Overview | Status, priority, assignee, timeline |
| Findings | Associated security findings |
| Activities | Audit trail of actions |
| Resolution | Step-by-step resolution documentation |

### Case Status Flow

```
Open -> In Progress -> Resolved -> Closed
```

### Resolution Steps

Document each resolution step with:
1. **Description**: What was done
2. **Action Taken**: Detailed explanation
3. **Result**: Outcome
4. **Timestamp**: Auto-recorded

### PDF Reports

Generate professional case reports with full timeline, findings, and resolution steps.

### Board Brief

One-page risk posture report designed for boards and CEOs. Triggered by saying "Generate board brief" or "Create board report" in the Vigil chat.

| Section | Contents |
|---------|----------|
| Risk posture | Red/yellow/green indicator with one-line summary |
| Key metrics | Validated kill chains, detection coverage %, MTTR, open criticals |
| Top 3 action items | Each with risk description, fix type (budget/policy/technical), and impact |
| 30/60/90 day trend | Exposure count direction — improving, stable, or degrading |

The board brief uses non-technical language throughout — no CVE numbers or ATT&CK IDs in the main body. All metrics are pulled from actual findings and case data.

The template is customizable at `docs/templates/board-brief.md`. Output is markdown in chat, with optional PDF export via the existing report pipeline.

**Quick commands:**
- "Generate board brief"
- "Create board report for last 30 days"
- "Generate risk posture report"

## Approval Workflow

Human-in-the-loop for autonomous actions.

### Confidence Thresholds

| Confidence | Normal Mode | Force Manual Mode |
|------------|-------------|-------------------|
| >= 0.90 | Auto-approved | Requires approval |
| 0.85-0.89 | Auto-approved + flag | Requires approval |
| 0.70-0.84 | Requires approval | Requires approval |
| < 0.70 | Monitor only | Monitor only |

### Force Manual Approval

Enable via **Dashboard > Approval Queue** checkbox.

Use when:
- Training/testing environment
- During active incidents
- New deployment (first weeks)
- Compliance requirements

### Action Types

- `isolate_host` - Network isolate compromised host
- `block_ip` - Block malicious IP
- `block_domain` - Block malicious domain
- `quarantine_file` - Quarantine malicious file
- `disable_user` - Disable compromised account
- `execute_spl_query` - Run Splunk query
- `custom` - Custom action

## AI Finding Enrichment

Automatic AI analysis cached on first view.

### Enrichment Contents

| Field | Description |
|-------|-------------|
| Threat Summary | Clear overview of the threat |
| Threat Type | Classification (exfiltration, lateral movement, etc.) |
| Risk Level | Critical, High, Medium, Low |
| Potential Impact | Business impact explanation |
| Recommended Actions | Prioritized response steps |
| Investigation Questions | Key questions for deeper analysis |
| Related Techniques | MITRE ATT&CK mapping |
| Indicators of Compromise | Malicious IPs, domains, processes |
| Confidence Score | AI's confidence (0-100%) |

### Usage

1. Open any finding detail view
2. Enrichment auto-generates on first view
3. Cached in database for instant retrieval
4. Optional: Force regeneration button

## Autonomous Response

Auto-Responder agent for automated containment.

### Multi-Source Correlation

1. Pull alerts from Tempo Flow (network)
2. Pull alerts from CrowdStrike (endpoint)
3. Correlate by IP, time, behavior
4. Calculate confidence score
5. Take action based on threshold

### Confidence Calculation

| Factor | Points |
|--------|--------|
| Multiple corroborating alerts | +0.20 |
| Critical severity | +0.15 |
| Lateral movement | +0.15 |
| Ransomware behavior | +0.25 |
| Time correlation | +0.10 |

### Example Flow

```
1. Detect suspicious IP
2. Query Tempo Flow -> Lateral movement detected
3. Query CrowdStrike -> Ransomware behavior
4. Calculate confidence: 0.85
5. Auto-isolate host (threshold met)
6. Report to analyst
```

## MITRE ATT&CK Integration

### Attack Layer Visualization

- View technique coverage
- Color-coded by severity/confidence
- Export to ATT&CK Navigator format

### Technique Rollup

- Count findings per technique
- Sort by prevalence
- Filter by time window

### MCP Tools

| Tool | Description |
|------|-------------|
| `get_attack_layer` | Current layer visualization |
| `get_technique_rollup` | Technique statistics |
| `get_findings_by_technique` | Findings for specific TID |
| `get_tactics_summary` | Tactic summary |
| `create_attack_layer` | Generate new layer |

## Chat Interface

AI-powered investigation assistant.

### Features

- Agent selection dropdown
- Streaming responses
- MCP tool integration
- Chat history
- Export conversations

### Quick Commands

- "Investigate finding f-xxx"
- "Create case for this finding"
- "Search Splunk for IP x.x.x.x"
- "What MITRE techniques are detected?"
- "Enrich this IOC"
- "Generate board brief"

## Desktop Notifications

Browser notifications for:
- New high-severity findings
- Approval requests
- Case updates
- Agent responses

Enable via browser notification permissions.
