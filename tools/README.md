# MCP tool servers

Each file here is a standalone MCP server over stdio. `mcp-config.json`
spawns it as its own `python3` subprocess — nothing in this directory is
imported by the API, the daemon or the worker.

## The 10 tools

| Tool | File | Outbound HTTP |
|---|---|---|
| AlienVault OTX | `alienvault_otx.py` | otx.alienvault.com |
| ANY.RUN | `anyrun.py` | api.any.run |
| Azure AD | `azure_ad.py` | login.microsoftonline.com, graph.microsoft.com |
| CAPE Sandbox | `cape_sandbox.py` | self-hosted CAPEv2 |
| Carbon Black | `carbon_black.py` | Carbon Black Cloud |
| Hybrid Analysis | `hybrid_analysis.py` | hybrid-analysis.com |
| IP geolocation | `ip_geolocation.py` | ip-api.com |
| Microsoft Teams | `microsoft_teams.py` | incoming webhook |
| MISP | `misp.py` | self-hosted MISP |
| Palo Alto | `palo_alto.py` | PAN-OS XML API |

`url_analysis.py` also sits here and is spawned the same way, but it only
parses URLs locally, so none of the HTTP conventions below apply to it.

A vendor that owns a slice under `core/integrations/` keeps its MCP server
there instead, next to that vendor's client and router — those are part of
the slice, not of this directory. `mcp-config.json` is the authority on where
any given server is spawned from.

## Conventions for outbound HTTP

`httpx` is the HTTP client — `requests` is no longer used in application code.

| | |
|---|---|
| `timeout=` | Required. httpx defaults to 5s, too short for a sandbox report or a SIEM search, so state a budget per call. |
| No `follow_redirects` | These are fixed API endpoints, so a 3xx means a wrong base URL, not a hop worth chasing. httpx doesn't follow redirects and `raise_for_status()` rejects a 3xx, which surfaces the misconfiguration. |
| `verify=config.get('verify_ssl', True)` | For on-prem appliances that may use self-signed certs. Never hardcode `verify=False` — the operator opts out. |
| `except httpx.HTTPStatusError` | The twin of `requests.HTTPError`. `httpx.HTTPError` is its parent and also catches transport failures, which belong to the generic handler. |

`tests/unit/integrations/test_tool_servers_httpx.py` scans this directory for
the timeout — easy to forget, silent when you do — and covers the rest with
respx-mocked round trips.
`tests/unit/_ratchets/test_no_tls_verify_disabled.py` fails CI on a
hardcoded `verify=False`.

## Adding one

1. Write the server here (or in the vendor's slice under
   `core/integrations/`), following the table above.
2. Add its entry to `mcp-config.json`.
3. Document it in `docs/INTEGRATIONS.md` and in the table above.
