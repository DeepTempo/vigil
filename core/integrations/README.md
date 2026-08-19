# Vendor slices

One directory per vendor. A slice holds whatever that vendor needs — a
`descriptor.py` declaring its config fields, a `client.py` for in-process calls,
a router, and `tool.py` if the vendor is exposed to agents as an MCP server.

`tool.py` is a standalone MCP server over stdio. `mcp-config.json` spawns it as
its own `python3` subprocess, so nothing in it is imported by the API, the
daemon or the worker — only by its own process and by tests.

Thirteen slices carry one today: `alienvault_otx`, `anyrun`, `azure_ad`,
`cape_sandbox`, `carbon_black`, `cloudflare`, `hybrid_analysis`,
`ip_geolocation`, `microsoft_defender`, `microsoft_teams`, `misp`, `palo_alto`,
`slack`. Four more — `elastic`, `splunk`, `url_analysis`, `vstrike` — ship a
`tool.py` that makes no outbound HTTP call at all. `mcp-config.json` is the
authority on which servers are actually spawned.

## Reading config

`resolve(DESCRIPTOR)` from `core.integrations._base.config` is the one way a
server reads its own config; `missing(config, 'url', 'api_key')` is the
"not configured" guard. Don't reach for `get_integration_config` directly — it
never sees secret fields, because `split_secrets` strips them before anything is
persisted.

`resolve()` returns **every** declared field, present-but-`None` when unset, so
`config.get('verify_ssl', True)` never fires its default. Write it out:

```python
verify = True if config.get('verify_ssl') is None else config.get('verify_ssl')
```

## Conventions for outbound HTTP

`httpx` is the HTTP client — `requests` is no longer used in application code.

| | |
|---|---|
| `timeout=` | Required. httpx defaults to 5s, too short for a sandbox report or a SIEM search, so state a budget per call. |
| No `follow_redirects` | httpx's default, and the one to keep — not something a server has to handle. Most servers hardcode their vendor's host, so a 3xx is unreachable anyway. It matters only for the five whose host is operator-supplied (`cape_sandbox`, `carbon_black`, `microsoft_teams`, `misp`, `palo_alto`): there a 3xx means a wrong base URL, and following it would be worse than surfacing it — on a POST, a 301/302/303 is re-issued as a GET without the body, so a "delivered" alert silently isn't. A handler that reads `status_code` instead of calling `raise_for_status()` must carry the status into its payload, or the failure is undiagnosable. |
| `verify=<resolved verify_ssl>` | For on-prem appliances that may use self-signed certs. Never hardcode `verify=False` — the operator opts out. |
| `except httpx.HTTPStatusError` | The twin of `requests.HTTPError`. `httpx.HTTPError` is its parent and also catches transport failures, which belong to the generic handler. |
| No `None` in `params=` | requests dropped a `None`-valued param; httpx sends `key=`. A tool call may carry `"limit": null`, so write `args.get("limit") or 20`, not `args.get("limit", 20)`. |

### CA bundles

To trust a private or inspecting CA, set **`SSL_CERT_FILE`** (a bundle file) or
**`SSL_CERT_DIR`** (a directory) in the backend's environment. `REQUESTS_CA_BUNDLE`
and `CURL_CA_BUNDLE` are honored as aliases for the `requests` era, translated to
the name httpx actually reads. Unset, httpx uses certifi.

`core/integrations/mcp/child_env.py` resolves this and every spawn site merges
it into the child environment. Forwarding has to be explicit: `mcp.client.stdio`
narrows a spawned server's environment to `HOME`, `LOGNAME`, `PATH`, `SHELL`,
`TERM`, `USER` plus its own `env` block, so a bundle set in the backend's
environment is otherwise stripped before the server sees it.

A path that doesn't exist is ignored with a warning rather than forwarded — a
stale value should not turn into a bundle that fails every TLS handshake.

## Tests

`tests/unit/integrations/test_tool_servers_httpx.py` scans every `tool.py` for
the timeout — easy to forget, silent when you do — and covers the rest with
respx-mocked round trips.
`tests/unit/_ratchets/test_no_tls_verify_disabled.py` fails CI on a hardcoded
`verify=False`.

## Adding one

1. Add the slice directory with a `descriptor.py`, then `tool.py` following the
   table above.
2. Add its entry to `mcp-config.json`.
3. Document it in `docs/INTEGRATIONS.md` and in the list above.
