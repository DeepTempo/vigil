# The Integration Descriptor is the integration registry

Integration facts had drifted across five places — `mcp-config.json` keys,
descriptor `id`, descriptor `mcp_server_name`, the frontend catalog `id`, and the
snake_case key each `tools/*.py` passed to `get_integration_config()`. The drift
was not cosmetic: six of the eleven `tools/` servers read a key the UI never
writes, every `"<x>-server"` value in `INTEGRATION_TO_SERVER_MAP` matched no real
server, and Carbon Black read a field name the UI never collects. We are making
the **Integration Descriptor** the one place a code-backed integration's registry
facts are stated, with every other registry deriving from it and a ratchet test
gating the parts that cannot.

## Two identifiers, kept separate

An integration has an **Integration Id** (persisted: primary key of
`integration_configs`, key in `integrations_config.json`, stem of each secret's
storage name) and zero or more **MCP Server Names** (running processes, and the
prefix on the tool names they expose). Collapsing them to one string is the
obvious simplification and we rejected it: renaming an Integration Id orphans a
DB row, a config entry, and an encrypted credential simultaneously, so it is a
data migration rather than an edit. Both stay, both are declared on the
descriptor, and CI asserts every server name resolves to a real
`mcp-config.json` key. No id is renamed — the drift is fixable without touching
anyone's stored config.

The server field is a tuple rather than a single name because one vendor can
back several servers: Splunk has both an official `npx` server and the
self-hosted one Vigil ships, and the config's own notes anticipate the same for
AlienVault OTX and Palo Alto as official servers mature. The same reasoning
settles field-name mismatches — where a server and the catalog disagree (Carbon
Black's `api_token` against the catalog's `api_id`/`api_key`, Palo Alto's `url`
against `hostname`), the catalog wins and the server adapts, because catalog
field names are already the storage names and renaming one orphans a credential.

## Credentials never come from the config file

`split_secrets()` strips every registered secret field before persisting to the
DB or JSON, so `get_integration_config()` cannot return a credential by design.
Any server reading one from there gets `None`. A descriptor-driven helper in
`core/integrations/_base/` is now the only way a server resolves config:
non-secrets from `get_integration_config(id)`, secrets from
`get_secret("<UPPER_ID>_<FIELD>")` using the descriptor's own field list. This
replaces `tools/base.py`, which was deleted as dead code in #585 — every server
had inlined its own copy instead.

A descriptor declares its **complete** field list, not just the secret ones, so
the helper returns a mapping keyed by declared fields and a server can only read
what its descriptor declares. That makes the catalog-parity check purely static —
descriptor fields against catalog fields — with no parsing of server source
anywhere. Descriptors are found by scanning `core/integrations/*/descriptor.py`,
mirroring the router scan in `services/api/discovery.py`, because the previous
import-list approach is exactly how the darktrace descriptor went dead in #557.

## Consequences

- No vendor server lives in the top-level `tools/` package. Every code-backed
  vendor owns `core/integrations/<vendor>/`; a vendor whose only presence is a
  third-party `mcp-config.json` entry still owns a descriptor-only slice, as
  `jira` already did. `tools/mcp/` is unaffected — those servers talk to Vigil's
  own services and are not Integrations.
- Catalog-only vendors — a credential form with no Vigil code — get no
  descriptor. `tests/unit/_ratchets/` gates their parity with the frontend
  catalog, following the `config.py` ↔ `env.example` precedent.
- The bridge's dynamic-load path is deleted rather than repaired. Every server
  Vigil runs is declared in `mcp-config.json`, and the path only ever spawned
  modules that do not exist.
