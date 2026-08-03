import json
import logging
from datetime import datetime
from typing import Any
import numpy as np
from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)


class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if isinstance(obj, datetime):
            return obj.isoformat() + 'Z'
        return super().default(obj)


def json_response(data: Any, indent: int = 2) -> str:
    return json.dumps(data, cls=NumpyEncoder, indent=indent)


def error_response(message: str, **extra) -> str:
    return json_response({"error": message, **extra})


def get_config(integration_id: str) -> dict:
    try:
        from core.config import get_integration_config
        return get_integration_config(integration_id)
    except ImportError:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from core.config import get_integration_config
        return get_integration_config(integration_id)


def create_server(name: str) -> FastMCP:
    return FastMCP(name)


def require_api_key(config: dict, service_name: str) -> tuple[str | None, str | None]:
    api_key = config.get('api_key')
    if not api_key:
        return None, error_response(
            f"{service_name} not configured",
            message=f"Configure {service_name} API key in Settings > Integrations"
        )
    return api_key, None
