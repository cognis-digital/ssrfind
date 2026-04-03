"""SSRFIND — Find SSRF-prone sinks and unvalidated URL fetches in code."""
from ssrfind.core import scan, TOOL_NAME, TOOL_VERSION
__all__ = ["scan", "TOOL_NAME", "TOOL_VERSION"]
