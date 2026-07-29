# Manual MCP smoke scripts

These scripts are exploratory checks for local MCP services. They are not part
of the automated pytest or frontend Vitest suites. Run one explicitly when the
required local service is available:

```bash
node scripts/mcp-smoke/<file>.js
```

They may require service-specific environment variables or a running local
endpoint. Do not add credentials or captured customer data to this directory.
