"""SSRFIND - find SSRF-prone sinks and unvalidated URL fetches in source code.

Defensive / authorized-testing static analysis only. SSRFIND reads source
files and reports locations where a network fetch consumes a URL that may be
attacker-influenced, so reviewers can add allow-listing / validation. It does
NOT perform any network requests against discovered targets.
"""
from .core import (
    Finding,
    Severity,
    scan_path,
    scan_source,
    SINK_RULES,
    TAINT_HINTS,
)

TOOL_NAME = "ssrfind"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Finding",
    "Severity",
    "scan_path",
    "scan_source",
    "SINK_RULES",
    "TAINT_HINTS",
    "TOOL_NAME",
    "TOOL_VERSION",
]
