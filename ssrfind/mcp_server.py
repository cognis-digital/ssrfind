"""SSRFIND MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import sys

from ssrfind.core import scan, to_json


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-ssrfind[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("Install the MCP extra: pip install 'cognis-ssrfind[mcp]'", file=sys.stderr)
        return 1
    app = FastMCP("ssrfind")

    @app.tool()
    def ssrfind_scan(target: str) -> str:
        """Find SSRF-prone sinks and unvalidated URL fetches in code. Returns JSON findings."""
        if not target or not isinstance(target, str):
            return '{"error": "target must be a non-empty string"}'
        try:
            findings = scan(target)
        except (FileNotFoundError, ValueError, OSError) as exc:
            return f'{{"error": {str(exc)!r}}}'
        return to_json(findings, scanned=target)

    app.run()
    return 0
