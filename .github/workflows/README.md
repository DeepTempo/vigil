# GitHub Actions Workflows

This directory contains the CI/CD workflows for AI-OpenSOC.

## Current Configuration: CI Only (Testing + Building)

The workflows are currently configured for **Continuous Integration** only - they test your code and build Docker images, but **don't deploy anywhere**.

### What Runs Automatically

✅ **On every push/PR**:
- Linting (Python, TypeScript, Dockerfile)
- Unit tests with coverage
- Integration tests  
- Security scanning
- Docker image building
- Container vulnerability scanning

✅ **Result**: 
- Tests verify your code works
- Docker images pushed to GitHub Container Registry
- No deployment needed!

## Workflows

### 1. `ci-cd.yml` - Main Testing Pipeline
- **Triggers**: Push or PR to main/develop
- **Purpose**: Test everything and build images
- **Deployment**: Disabled (testing only)

### 2. `release.yml` - Release Management  
- **Triggers**: Version tags (v1.0.0)
- **Purpose**: Create GitHub releases
- **Deployment**: Disabled (would deploy to production VMs)

### 3. `nightly.yml` - Scheduled Testing
- **Triggers**: Daily at 2 AM UTC
- **Purpose**: Comprehensive testing and security audits
- **Deployment**: None

## No Secrets Required!

Since deployment is disabled, you **don't need to configure**:
- ❌ SSH_PRIVATE_KEY
- ❌ VM_HOST variables  
- ❌ SLACK_WEBHOOK_URL
- ❌ SENTRY_DSN

The only "secret" used is `GITHUB_TOKEN` which is **automatically provided** by GitHub Actions.

## Running Your App Manually

After the CI builds your images, you can run them anywhere:

```bash
# Pull the built images
docker pull ghcr.io/deeptempo/ai-opensoc-backend:main
docker pull ghcr.io/deeptempo/ai-opensoc-daemon:main

# Run with Docker Compose V2
docker compose up -d
```

## Future: Enabling Deployment

When you're ready to auto-deploy, see:
- `docs/CI_CD_GUIDE.md` - Full CI/CD documentation
- `docs/DEPLOYMENT_GUIDE.md` - VM deployment guide

To enable:
1. Uncomment the `deploy-staging` job in `ci-cd.yml`
2. Add required secrets to GitHub
3. Configure your VMs

But for now - **pure CI testing works perfectly!** ✅

