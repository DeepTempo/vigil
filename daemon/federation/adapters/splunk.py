"""Deprecated shim: moved to core.integrations.splunk.adapter (reorg #483).

Importing re-runs the register_adapter() side effect so the federation
registry's builtin import still registers Splunk. Removed in #489.
"""

from core.integrations.splunk.adapter import SplunkAdapter  # noqa: F401
