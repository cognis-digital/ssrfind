"""SSRFIND MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from ssrfind.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-ssrfind[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-ssrfind[mcp]'")
        return 1
    app = FastMCP("ssrfind")

    @app.tool()
    def ssrfind_scan(target: str) -> str:
        """Find SSRF-prone sinks and unvalidated URL fetches in code. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
