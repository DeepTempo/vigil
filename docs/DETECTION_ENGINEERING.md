# Detection Engineering

Vigil integrates 7,200+ security detection rules and exposes them to Claude agents via 5 backend tools for coverage analysis and detection search.

## Overview

- **7,200+ Detection Rules** across Sigma, Splunk ESCU, Elastic, and KQL formats
- **5 Backend Tools** available to all agents via Agent SDK (no additional config)
- **MITRE ATT&CK Integration** — map detections to techniques and visualize gaps

## Setup

Detection repositories are automatically cloned during `./scripts/setup_dev.sh` (~4GB download):

```bash
./scripts/setup_dev.sh
```

To skip detection repos during setup:
```bash
SKIP_DETECTION_REPOS=true ./scripts/setup_dev.sh
```

To update existing repositories:
```bash
./scripts/setup_detection_repos.sh --update
```

Verify installation:
```bash
python scripts/test_detection_integration.py
```

## Detection Tools (5 Backend Tools)

These are the tools available to all agents via function calling. Defined in `backend/schemas/tool_schemas.py`.

### `analyze_coverage`

Check how many detection rules cover specific MITRE ATT&CK techniques across all formats.

```
analyze_coverage(techniques=["T1059.001", "T1071.001"])
```

Returns: rule count and list of detections per technique, broken down by format (Sigma, Splunk, Elastic, KQL).

### `search_detections`

Full-text search across all 7,200+ rules.

```
search_detections(query="powershell base64", source_type="sigma", limit=20)
```

`source_type` is optional — omit to search all formats.

### `identify_gaps`

Identify which MITRE techniques have insufficient detection coverage for a given threat context.

```
identify_gaps(context="ransomware")
identify_gaps(context="APT29")
identify_gaps(context="lateral movement")
```

### `get_coverage_stats`

Get aggregate statistics — total rule count, technique coverage, and breakdown by format.

```
get_coverage_stats()
get_coverage_stats(source_type="splunk")
```

### `get_detection_count`

Get rule count, optionally filtered by format.

```
get_detection_count()
get_detection_count(source_type="elastic")
```

## Workflows

### Coverage Assessment

```
You: "Switch to MITRE Analyst"
You: "What's our detection coverage for ransomware?"

Claude: [identify_gaps("ransomware")]
        "Weak coverage for:
         - T1486 (Data Encrypted for Impact): 2 detections
         - T1490 (Inhibit System Recovery): 1 detection
         Recommendation: Prioritize T1486"

You: "Search for existing T1486 detections"
Claude: [search_detections("ransomware file encryption")]
        "Found 8 matching rules..."

You: "Get our overall Splunk coverage stats"
Claude: [get_coverage_stats(source_type="splunk")]
        "3,240 Splunk rules covering 187 ATT&CK techniques..."
```

### Investigation Coverage Validation

```
You: "Switch to Investigator"
You: "Would PowerShell obfuscation attacks be detected in our environment?"

Claude: [analyze_coverage(["T1059.001", "T1027"])]
        "T1059.001: 234 rules (strong coverage)
         T1027: 45 rules (moderate coverage)
         Recommended: Review T1027 detections for obfuscation variants"

You: "Show me what specific detections cover T1059.001"
Claude: [search_detections("powershell execution", source_type="splunk")]
        "Found 47 Splunk rules matching PowerShell execution..."
```

## Configuration

### Detection Repository Paths (`.env`)

```bash
SIGMA_PATHS="${HOME}/security-detections/sigma/rules"
SPLUNK_PATHS="${HOME}/security-detections/security_content/detections"
ELASTIC_PATHS="${HOME}/security-detections/detection-rules/rules"
KQL_PATHS="${HOME}/security-detections/Hunting-Queries-Detection-Rules"
STORY_PATHS="${HOME}/security-detections/security_content/stories"
```

### Updating Repositories

```bash
./scripts/setup_detection_repos.sh --update

# Verify rule counts
find ~/security-detections/sigma/rules -name "*.yml" | wc -l
find ~/security-detections/security_content/detections -name "*.yml" | wc -l
```

## Troubleshooting

### Detection Repositories Not Found

```bash
ls -l ~/security-detections/
# If empty or missing:
./scripts/setup_detection_repos.sh
```

### Low Detection Count

The rule loader expects the repositories at the paths configured in `.env`. Check that `SIGMA_PATHS`, `SPLUNK_PATHS`, `ELASTIC_PATHS`, and `KQL_PATHS` point to valid directories with `.yml` files.

### Tools Not Responding

Restart the backend — detection rules are indexed in memory on first use:
```bash
./start_web.sh
```
