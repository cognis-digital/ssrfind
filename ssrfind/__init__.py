"""ssrfind — part of the Cognis Neural Suite."""
from ssrfind.core import (  # noqa: F401
    Finding,
    Severity,
    TOOL_NAME,
    TOOL_VERSION,
    scan_source,
    scan_path,
    scan,
    to_json,
)

__version__ = TOOL_VERSION
