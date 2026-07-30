import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGES = ("backend", "services", "daemon", "core", "database")

# Files where reading os.environ is the point, not a violation. The secrets
# manager implements the environment backend; mcp_service exports config into
# spawned MCP child processes, whose config protocol *is* env vars.
ENV_EXEMPT_FILES = {
    "backend/secrets_manager.py",
}

# Existing module-level instantiations. Converting these to accessor calls is
# import-timing churn across many handlers, so they are grandfathered by name.
SINGLETON_ALLOWED = {
    ("backend/api/agents.py", "agent_manager"),
    ("backend/api/analytics.py", "ai_insights_service"),
    ("backend/api/attack.py", "data_service"),
    ("backend/api/case_metrics.py", "metrics_service"),
    ("backend/api/case_search.py", "search_service"),
    ("backend/api/case_templates.py", "workflow_service"),
    ("backend/api/cases.py", "data_service"),
    ("backend/api/custom_agents.py", "service"),
    ("backend/api/findings.py", "data_service"),
    ("backend/api/vstrike.py", "data_service"),
    ("services/case_automation_service.py", "automation_service"),
    ("services/ingestion_jobs.py", "_registry"),
}

# Not yet migrated onto Settings. Shrinks to empty as the migration lands;
# a file leaving this list can never come back, which is the ratchet.
MIGRATION_PENDING = {
    "backend/api/auth.py",
    "backend/api/cloudflare_webhooks.py",
    "backend/api/config.py",
    "backend/api/darktrace_webhook.py",
    "backend/api/ingestion.py",
    "backend/api/kafka.py",
    "backend/api/vstrike.py",
    "backend/main.py",
    "backend/middleware/auth.py",
    "backend/middleware/csrf.py",
    "backend/middleware/rate_limit.py",
    "backend/middleware/security_headers.py",
    "backend/monitoring.py",
    "backend/services/auth_cookies.py",
    "backend/services/auth_service.py",
    "backend/services/email_service.py",
    "backend/services/password_reset.py",
    "backend/services/password_validator.py",
    "backend/services/token_blacklist.py",
    "core/telemetry.py",
    "core/telemetry_config.py",
    "daemon/dedup.py",
    "daemon/federation/runner.py",
    "daemon/llm_worker_manager.py",
    "daemon/metrics.py",
    "daemon/orchestrator.py",
    "daemon/sandbox_poller.py",
    "daemon/sandbox_submitter.py",
    "daemon/scheduler.py",
    "daemon/shared_intel.py",
    "daemon/threat_feed_poller.py",
    "database/connection.py",
    "services/autostart_config.py",
    "services/bifrost_admin.py",
    "services/bifrost_cost_client.py",
    "services/budget_service.py",
    "services/claude_service.py",
    "services/cost_estimator.py",
    "services/defaults.py",
    "services/extension_trust.py",
    "services/integration_bridge_service.py",
    "services/llm_clients.py",
    "services/llm_gateway.py",
    "services/llm_router.py",
    "services/llm_worker.py",
    "services/local_ai_recovery.py",
    "services/mcp_client.py",
    "services/mcp_service.py",
    "services/mempalace_paths.py",
    "services/model_registry.py",
    "services/ollama_process.py",
    "services/prompt_security.py",
    "services/provider_model_discovery.py",
    "services/runtime_config.py",
    "services/service_manager.py",
    "services/vstrike_service.py",
}

SERVICE_SUFFIXES = ("Service", "Registry", "Manager", "Client")

# Not a service: the FastAPI router and the SQLAlchemy/limiter primitives are
# module-level by design in every FastAPI codebase.
SINGLETON_IGNORED_CALLEES = {"APIRouter", "Limiter", "HTTPBearer", "Path"}


def _python_files():
    for package in PACKAGES:
        for path in sorted((REPO_ROOT / package).rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            yield path.relative_to(REPO_ROOT)


def _parse(rel_path: Path):
    source = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    return source.splitlines(), ast.parse(source)


def _callee_name(node: ast.AST):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _env_reads(rel_path: Path):
    lines, tree = _parse(rel_path)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute) or node.attr not in ("getenv", "environ"):
            continue
        if not (isinstance(node.value, ast.Name) and node.value.id == "os"):
            continue
        if "noqa: ENV001" in lines[node.lineno - 1]:
            continue
        yield node.lineno, lines[node.lineno - 1].strip()


def _module_level_services(rel_path: Path):
    _, tree = _parse(rel_path)
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        if not isinstance(node.value, ast.Call):
            continue
        callee = _callee_name(node.value.func)
        if not callee or callee in SINGLETON_IGNORED_CALLEES:
            continue
        if not callee.endswith(SERVICE_SUFFIXES):
            continue
        targets = [node.target] if isinstance(node, ast.AnnAssign) else node.targets
        for target in targets:
            if isinstance(target, ast.Name):
                yield node.lineno, target.id, callee


@pytest.mark.unit
def test_no_raw_env_reads():
    violations = []
    for rel_path in _python_files():
        if rel_path.as_posix() in ENV_EXEMPT_FILES | MIGRATION_PENDING:
            continue
        for lineno, text in _env_reads(rel_path):
            violations.append(f"{rel_path}:{lineno}: {text}")
    assert not violations, (
        "Raw environment reads found. Use core.config.get_settings() for config "
        "and get_secret() for credentials. If the read is a genuine process "
        "boundary, append '# noqa: ENV001' with a reason.\n" + "\n".join(violations)
    )


@pytest.mark.unit
def test_no_module_level_service_instantiation():
    violations = []
    for rel_path in _python_files():
        for lineno, name, callee in _module_level_services(rel_path):
            if (rel_path.as_posix(), name) in SINGLETON_ALLOWED:
                continue
            violations.append(f"{rel_path}:{lineno}: {name} = {callee}(...)")
    assert not violations, (
        "Module-level service instantiation found. Build the instance inside a "
        "get_*() accessor so import order and test isolation stay predictable.\n"
        + "\n".join(violations)
    )
