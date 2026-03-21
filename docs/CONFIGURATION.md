# Configuration

## Environment Variables

Copy `env.example` to `~/.deeptempo/.env` and configure:

```bash
cp env.example ~/.deeptempo/.env
chmod 600 ~/.deeptempo/.env
```

### Required

| Variable | Description |
|----------|-------------|
| `CLAUDE_API_KEY` | Anthropic Claude API key ([get one](https://console.anthropic.com/)) |
| `POSTGRESQL_CONNECTION_STRING` | PostgreSQL connection (default in Compose stack / `docker/docker-compose.yml`) |

### Optional Integrations

| Variable | Service |
|----------|---------|
| `AWS_ACCESS_KEY_ID` | S3 storage |
| `AWS_SECRET_ACCESS_KEY` | S3 storage |
| `TIMESKETCH_PASSWORD` | Timeline analysis |
| `SPLUNK_PASSWORD` | SIEM integration |
| `CRIBL_PASSWORD` | Data pipeline |
| `GITHUB_TOKEN` | MCP GitHub server |

### Secrets Backend

| Variable | Values | Description |
|----------|--------|-------------|
| `SECRETS_BACKEND` | `dotenv` (default), `env`, `keyring` | Where to write secrets |
| `ENABLE_KEYRING` | `false` (default), `true` | Enable OS keyring for reading |

## Secrets Priority

When reading, backends are checked in order:
1. Process environment variables
2. `~/.deeptempo/.env` file
3. OS keyring (only if `ENABLE_KEYRING=true`)

## Deployment Examples

### Local Development

```bash
./start_web.sh
```

### Docker

```bash
docker run --env-file ~/.deeptempo/.env deeptempo-ai-soc
```

### Docker Compose

```yaml
services:
  deeptempo:
    image: deeptempo-ai-soc
    ports:
      - "6987:6987"
    env_file:
      - ~/.deeptempo/.env
```

### Systemd

```ini
[Service]
EnvironmentFile=/etc/deeptempo/.env
ExecStart=/opt/deeptempo/venv/bin/uvicorn backend.main:app --host 0.0.0.0 --port 6987
```

### Kubernetes

```bash
kubectl create secret generic deeptempo-secrets \
  --from-literal=CLAUDE_API_KEY="sk-ant-..." \
  --from-literal=POSTGRESQL_CONNECTION_STRING="postgresql://..."
```

```yaml
envFrom:
  - secretRef:
      name: deeptempo-secrets
```

## UI Configuration

Most integrations are configured via **Settings > Integrations** in the web UI:

- API endpoints, usernames, non-sensitive config
- Passwords/secrets reference environment variables
- Test connection before saving

## PostgreSQL Setup

Default connection (matches `docker-compose.yml`):

```
postgresql://deeptempo:deeptempo_secure_password_change_me@localhost:5432/deeptempo_soc
```

Start database:

```bash
docker compose up -d postgres
```

## Security Best Practices

1. Never commit `.env` files to git
2. Use `chmod 600` on secret files
3. Rotate API keys periodically
4. Use separate secrets per environment (dev/staging/prod)
