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
            return obj.isoformat() + "Z"
        return super().default(obj)


def json_response(data: Any, indent: int = 2) -> str:
    return json.dumps(data, cls=NumpyEncoder, indent=indent)


def error_response(message: str, **extra) -> str:
    return json_response({"error": message, **extra})


def create_server(name: str) -> FastMCP:
    return FastMCP(name)


# There is deliberately no config/credential helper here. These servers talk to
# Vigil's own services and hold no vendor credentials; an Integration reads its
# config through core.integrations._base.config.resolve, which knows that
# get_integration_config never returns a secret.
