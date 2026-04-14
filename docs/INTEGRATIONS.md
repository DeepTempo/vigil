# Integrations

Configure integrations via **Settings > Integrations** in the web UI.

## Backend Tools via Agent SDK (Recommended)

**NEW**: Backend tool integration via Claude Agent SDK eliminates desktop dependency.

### Available Tools (19)

| Category | Count | Tools |
|----------|-------|-------|
| **Security Detections** | 5 | Coverage analysis, detection search, gap identification |
| **Findings & Cases** | 7 | List/get findings, case management, similarity search |
| **MITRE ATT&CK** | 2 | Attack layer generation, technique rollup |
| **Approval Workflow** | 5 | Pending approvals, approve/reject actions, statistics |

### Benefits

- ✅ **Zero Desktop Dependency** - Works entirely through Agent SDK
- ✅ **Web UI Compatible** - All tools accessible via browser
- ✅ **Production Ready** - Multi-user deployments
- ✅ **Lower Latency** - Direct function calls via Agent SDK
- ✅ **Simpler Deployment** - No MCP server configuration needed

### Usage

Backend tools are automatically enabled for web UI users via the Claude Agent SDK. See [Backend Tools Guide](BACKEND_TOOLS.md) for detailed documentation.

## MCP Servers (Optional - Advanced Integration)

> **Note**: MCP servers are optional and primarily used for advanced integrations requiring external services (Splunk, VirusTotal, etc.). Web UI users get full functionality through the Agent SDK backend tools.

| Category | Servers | Status |
|----------|---------|--------|
| Core | deeptempo-findings, approval, attack-layer, tempo-flow | Implemented |
| Community | GitHub, PostgreSQL | Active |
| Detection Engineering | Security-Detections-MCP | Implemented |
| SIEM | Splunk, Elastic Security | Implemented |
| Timeline | Timesketch | Implemented |
| Threat Intel | VirusTotal, Shodan, AlienVault OTX, MISP, URL Analysis, IP Geolocation | Implemented |
| EDR | CrowdStrike | Implemented |
| Sandbox | Hybrid Analysis, Joe Sandbox, ANY.RUN | Implemented |
| Ticketing | Jira | Implemented |
| Communication | Slack | Implemented |
| Data Pipeline | Cribl Stream | Implemented |

## Security-Detections-MCP

Detection engineering with 7,200+ rules across Sigma, Splunk ESCU, Elastic, and KQL formats.

### Overview

Security-Detections-MCP provides:
- **7,200+ Detection Rules** - Comprehensive detection rule database
- **71+ Tools** - Coverage analysis, gap identification, template generation
- **11 Expert Prompts** - Guided detection engineering workflows
- **Tribal Knowledge** - Document and retrieve detection decisions
- **Pattern Intelligence** - Learn from existing detection rules

### Configuration

Automatically configured during `./setup_dev.sh`. Detection repositories are cloned to `~/security-detections/`.

To skip automatic installation:
```bash
SKIP_DETECTION_REPOS=true ./setup_dev.sh
```

To update repositories:
```bash
./scripts/setup_detection_repos.sh --update
```

### Key Tool Categories

| Category | Tools | Description |
|----------|-------|-------------|
| Coverage Analysis | 6 tools | Quantify detection coverage by MITRE technique |
| Detection Search | 12 tools | Find relevant detection rules |
| Pattern Intelligence | 15 tools | Learn from existing detection patterns |
| Template Generation | 8 tools | AI-assisted detection rule creation |
| Tribal Knowledge | 20 tools | Document and retrieve detection decisions |
| Analytics & Reporting | 10 tools | Metrics and gap analysis reports |

### Expert Workflow Prompts

11 guided workflows for detection engineering:
- `apt-threat-emulation` - Purple team exercises for APT groups
- `coverage-analysis` - Comprehensive coverage assessment
- `detection-tuning` - Optimize existing detections
- `gap-prioritization` - Prioritize detection gaps
- `mitre-mapping` - Map findings to ATT&CK framework
- `purple-team-report` - Generate purple team reports
- `threat-landscape-sync` - Align to current threat landscape
- `detection-validation` - Validate detection effectiveness
- `sigma-to-platform` - Convert Sigma to platform-specific
- `coverage-heatmap` - Visualize detection coverage
- `detection-lifecycle` - Manage detection lifecycle

### Primary Use Cases

**For MITRE Analyst Agent:**
```
"What's our detection coverage for APT29?"
"What detection gaps exist for ransomware?"
"Generate a Splunk detection for T1059.001 PowerShell execution"
```

**For Threat Hunter Agent:**
```
"What patterns exist for detecting C2 beaconing?"
"Extract common fields used in PowerShell detections"
"Show me similar detections to the one we just created"
```

**For Investigator Agent:**
```
"Would our current detections catch this attack?"
"What detections exist for technique T1071.001?"
"Document why we prioritized this detection"
```

### Documentation

See [DETECTION_ENGINEERING.md](DETECTION_ENGINEERING.md) for complete usage guide, examples, and best practices.

### Verification

Test integration:
```bash
python scripts/test_detection_integration.py
```

## Splunk

Natural language to SPL query generation.

### Configuration

```bash
SPLUNK_PASSWORD="your_password"
```

Settings > Integrations > Splunk:
- Server URL: `https://splunk.example.com:8089`
- Username
- Verify SSL

### MCP Tools

| Tool | Description |
|------|-------------|
| `generate_spl_query` | Natural language to SPL |
| `execute_spl_search` | Run SPL query |
| `search_by_ip` | Quick IP search |
| `search_by_hostname` | Quick hostname search |
| `search_by_username` | Quick user search |
| `natural_language_search` | Generate and execute |
| `get_splunk_indexes` | List available indexes |

## Elastic Security

Elasticsearch SIEM with detection alert ingestion, bi-directional case sync, and IOC enrichment.

### Configuration

```bash
ELASTIC_HOST="https://elasticsearch.example.com:9200"
ELASTIC_KIBANA_URL="https://kibana.example.com:5601"
ELASTIC_API_KEY="your_api_key"
# Or use basic auth:
# ELASTIC_USERNAME="elastic"
# ELASTIC_PASSWORD="your_password"
```

Settings > Integrations > Elastic Security (SIEM):
- Elasticsearch URL
- Kibana URL (required for detection alerts and case sync)
- API Key or Username/Password
- Alert Index Pattern (default: `.alerts-security.alerts-default`)

### MCP Tools

| Tool | Description |
|------|-------------|
| `elastic_search_logs` | Search Elasticsearch with query DSL |
| `elastic_search_by_ioc` | Search by IOC (IP, hash, username, hostname) |
| `elastic_get_indices` | List available indices |
| `elastic_get_detection_alerts` | Fetch recent detection alerts |

### Features

- **Alert Ingestion**: Daemon poller fetches detection alerts from Kibana Detections API
- **Bi-directional Sync**: Case status changes in Vigil sync back to Elastic Security alerts
- **IOC Enrichment**: Agents query Elasticsearch indices for logs matching case IOCs

## Timesketch

Forensic timeline analysis.

### Configuration

Settings > Integrations > Timesketch:
- Server URL: `http://localhost:5000` (local) or production URL
- Auth: Username/Password or API Token
- Auto-sync interval (optional)

### MCP Tools

| Tool | Description |
|------|-------------|
| `list_sketches` | List investigation workspaces |
| `get_sketch` | Get sketch details |
| `create_sketch` | Create new workspace |
| `search_timesketch` | Lucene query search |
| `export_to_timesketch` | Export findings/cases |

## Threat Intelligence

### VirusTotal

```bash
# Settings > Integrations > VirusTotal
VT_API_KEY="your_api_key"
```

Tools: `vt_check_hash`, `vt_check_ip`, `vt_check_domain`, `vt_check_url`

### Shodan

```bash
SHODAN_API_KEY="your_api_key"
```

Tools: `shodan_search_ip`, `shodan_get_host_info`, `shodan_search_exploits`

### AlienVault OTX

```bash
OTX_API_KEY="your_api_key"
```

Tools: `otx_get_indicator`, `otx_search_pulses`, `otx_get_pulse`

### MISP

```bash
MISP_URL="https://misp.example.com"
MISP_API_KEY="your_api_key"
```

Tools: `misp_search`, `misp_get_event`, `misp_add_attribute`

## Sandbox Analysis

### Hybrid Analysis

```bash
HYBRID_ANALYSIS_API_KEY="your_api_key"
```

Tools: `ha_submit_file`, `ha_get_report`, `ha_search`

### Joe Sandbox

```bash
JOE_SANDBOX_API_KEY="your_api_key"
```

Tools: `joe_submit`, `joe_get_report`, `joe_search`

### ANY.RUN

```bash
ANYRUN_API_KEY="your_api_key"
```

Tools: `anyrun_get_report`, `anyrun_search`, `anyrun_get_iocs`

## EDR/XDR

### CrowdStrike

```bash
CS_CLIENT_ID="your_client_id"
CS_CLIENT_SECRET="your_client_secret"
```

Tools: `get_crowdstrike_alert_by_ip`, `crowdstrike_foundry_isolate`, `crowdstrike_foundry_unisolate`, `get_host_status`

## Communication

### Slack

```bash
SLACK_BOT_TOKEN="xoxb-..."
SLACK_DEFAULT_CHANNEL="#soc-alerts"
```

Tools: `slack_send_message`, `slack_send_alert`, `slack_create_channel`, `slack_upload_file`

### Jira

```bash
JIRA_URL="https://company.atlassian.net"
JIRA_EMAIL="user@company.com"
JIRA_API_TOKEN="your_token"
```

Tools: `jira_create_issue`, `jira_update_issue`, `jira_add_comment`, `jira_search`, `jira_get_issue`

## Data Pipeline

### Cribl Stream

```bash
CRIBL_PASSWORD="your_password"
CRIBL_WORKER_GROUP="default"
```

Benefits:
- Normalize log formats before DeepTempo analysis
- Filter noise, reduce Splunk ingestion 30-50%
- Enrich events with GeoIP, asset info
- Route data to multiple destinations

```
Data Sources -> Cribl Stream -> DeepTempo LogLM
                            -> Splunk
                            -> S3/Data Lake
```

## Adding Custom Integrations

Settings > Integrations > Custom Integration Builder:

1. Upload API documentation
2. AI generates MCP server code
3. Review and test
4. Deploy to `tools/` directory

## Stub Servers (Not Implemented)

Available for future implementation:

| Server | Category |
|--------|----------|
| AWS Security Hub | Cloud |
| Azure Sentinel | Cloud |
| GCP Security | Cloud |
| Azure AD | Identity |
| Okta | Identity |
| Microsoft Defender | EDR |
| SentinelOne | EDR |
| Carbon Black | EDR |
| PagerDuty | Communication |
