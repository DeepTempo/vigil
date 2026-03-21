# Vigil SOC

AI-powered Security Operations Center built on Claude and the Claude Agent SDK.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Browser (6988)                           │
│                      React / TypeScript UI                       │
└─────────────────────────────────────────────────────────────────┘
                              │ HTTP
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FastAPI Backend (6987)                         │
│          API Endpoints │ Tool Routing │ Claude Service           │
└─────────────────────────────────────────────────────────────────┘
                              │ Agent SDK
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Claude (claude-sonnet-4-6)                      │
│         Orchestrates 13 specialized SOC agents                   │
└─────────────────────────────────────────────────────────────────┘
                              │ Function calling (23 backend tools)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Backend Tools                              │
│   Findings │ Cases │ Detection Rules │ ATT&CK │ Approvals       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  PostgreSQL + pgvector                            │
│         Findings │ Cases │ Embeddings │ AI Decisions            │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

| Component | Purpose |
|-----------|---------|
| **FastAPI Backend** | REST API, Claude orchestration, tool routing |
| **Claude Agent SDK** | Autonomous multi-step investigation via 23 backend tools |
| **13 SOC Agents** | Specialized agents for triage, hunting, forensics, response, etc. |
| **4 Skills** | Multi-agent orchestrated workflows (Incident Response, Threat Hunt, etc.) |
| **PostgreSQL** | Findings, cases, embeddings, audit logs, approvals |

## Navigation

| Page | Path | Purpose |
|------|------|---------|
| Dashboard | `/` | Metrics, recent findings, system status |
| Findings | `/findings` | Security findings, AI investigation |
| Cases | `/cases` | Case management, timelines |
| Skills | `/skills` | Run multi-agent workflows |
| AI Decisions | `/ai-decisions` | Approval queue for autonomous actions |
| Timesketch | `/timesketch` | Timeline forensic analysis |
| Settings | `/settings` | API keys, integrations, MCP servers |

## Quick Start

1. Configure Claude API key: **Settings > Claude API**
2. Ingest findings via `/api/ingest` or configure a data source integration
3. Investigate findings: **Findings > Click any finding > Investigate**
4. Run multi-agent workflows: **Skills > Select skill**

## Data Flow

1. **Ingest**: Findings arrive via REST API or SIEM polling (Splunk, CrowdStrike, etc.)
2. **Store**: PostgreSQL holds findings, cases, embeddings
3. **Query**: Claude invokes backend tools to search/filter findings
4. **Analyze**: 13 specialized agents guide investigation via skills
5. **Respond**: Approval workflow gates containment actions
6. **Document**: Cases, ATT&CK Navigator layers, reports

## Documentation

- [CONFIGURATION.md](CONFIGURATION.md) - Environment variables, secrets, setup
- [AGENTS.md](AGENTS.md) - 13 specialized SOC AI agents and 4 skills
- [INTEGRATIONS.md](INTEGRATIONS.md) - Splunk, CrowdStrike, VirusTotal, and more
- [FEATURES.md](FEATURES.md) - Cases, approvals, enrichment, reports
- [API.md](API.md) - Backend tool contracts and data models
- [BACKEND_TOOLS.md](BACKEND_TOOLS.md) - Detailed tool documentation
- [DETECTION_ENGINEERING.md](DETECTION_ENGINEERING.md) - Detection rule coverage analysis
