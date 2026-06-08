"""Core SSRF static-analysis engine (stdlib only).

Strategy
--------
We scan source line-by-line for known HTTP-fetch *sinks* (requests.get,
urllib.request.urlopen, httpx, aiohttp, socket.connect, ...). For each sink we
inspect the argument expression and surrounding context to decide whether the
URL/host fed to the sink looks attacker-influenced ("tainted") versus a static
literal. Tainted, unvalidated fetches are the SSRF hotspots.

This is a heuristic linter (like `semgrep` SSRF rules), not a full dataflow
engine. It is intentionally conservative about marking things SAFE: a static
string literal with no taint hint is downgraded, everything else is reported.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Iterable, List, Optional


class Severity(str, Enum):
    HIGH = "high"      # tainted URL into a fetch sink, no visible validation
    MEDIUM = "medium"  # variable URL into a sink, taint unclear
    LOW = "low"        # sink present but argument looks like a static literal


# (rule_id, sink regex, human label). The capture group (arg) holds the call's
# first argument expression, which we then classify for taint.
SINK_RULES = [
    ("py.requests", re.compile(r"\brequests\.(?:get|post|put|delete|head|patch|request)\s*\(\s*([^,)]+)"), "requests.* fetch"),
    ("py.urllib", re.compile(r"\b(?:urllib\.request\.)?urlopen\s*\(\s*([^,)]+)"), "urllib urlopen"),
    ("py.urllib.Request", re.compile(r"\b(?:urllib\.request\.)?Request\s*\(\s*([^,)]+)"), "urllib Request"),
    ("py.httpx", re.compile(r"\bhttpx\.(?:get|post|put|delete|head|patch|request|stream|Client\(\)\.\w+)\s*\(\s*([^,)]+)"), "httpx fetch"),
    ("py.aiohttp", re.compile(r"\.(?:get|post|put|delete|head|patch|request)\s*\(\s*([^,)]+)\s*\)\s*(?:#.*)?$"), "aiohttp/session fetch"),
    ("py.socket", re.compile(r"\b\w+\.connect\s*\(\s*\(\s*([^,)]+)"), "socket.connect host"),
    ("py.pycurl", re.compile(r"\.setopt\s*\(\s*pycurl\.URL\s*,\s*([^,)]+)"), "pycurl URL"),
    ("js.fetch", re.compile(r"\bfetch\s*\(\s*([^,)]+)"), "fetch()"),
    ("js.axios", re.compile(r"\baxios\.(?:get|post|put|delete|head|patch|request)?\s*\(\s*([^,)]+)"), "axios fetch"),
    ("js.http", re.compile(r"\b(?:http|https)\.(?:get|request)\s*\(\s*([^,)]+)"), "node http(s) request"),
    ("js.gotrequest", re.compile(r"\b(?:got|request|superagent\.get)\s*\(\s*([^,)]+)"), "got/request fetch"),
]

# Substrings in the URL-argument expression that suggest external/user control.
TAINT_HINTS = [
    "request", "req.", "params", "query", "args", "form", "body", "payload",
    "input", "user", "data[", "data.", "get(", "json", "headers", "cookie",
    "env", "argv", "event", "message", "msg", "target", "dest", "url",
    "host", "endpoint", "callback", "webhook", "uri", "addr", "remote",
    "f\"", "f'", "format(", "+", "%s", "${", "`",
]

# Tokens indicating validation/allow-listing is applied nearby (lowers severity).
VALIDATION_HINTS = [
    "allowlist", "allow_list", "whitelist", "is_allowed", "allowed_hosts",
    "validate_url", "validate(", "is_safe", "safe_url", "urlparse",
    "ipaddress", "is_private", "resolve", "netloc in", "hostname in",
    "startswith(", "raise ", "abort(", "reject",
]

LITERAL_RE = re.compile(r"""^\s*(?:[a-zA-Z_]+)?[\"']https?://[^\"'{}$%`+]+[\"']\s*$""")
SCAN_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".mypy_cache"}


@dataclass
class Finding:
    file: str
    line: int
    rule_id: str
    sink: str
    severity: str
    argument: str
    snippet: str
    reason: str
    tainted: bool = False
    validated_nearby: bool = False
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _arg_is_literal(arg: str) -> bool:
    return bool(LITERAL_RE.match(arg.strip()))


def _arg_taint_hits(arg: str) -> List[str]:
    a = arg.lower()
    return [h for h in TAINT_HINTS if h.lower() in a]


def _context_validation(lines: List[str], idx: int, window: int = 6) -> List[str]:
    lo = max(0, idx - window)
    hi = min(len(lines), idx + window + 1)
    blob = "\n".join(lines[lo:hi]).lower()
    return [v for v in VALIDATION_HINTS if v in blob]


def _classify(arg: str, lines: List[str], idx: int) -> tuple[Severity, bool, bool, str, List[str]]:
    arg = arg.strip()
    taint_hits = _arg_taint_hits(arg)
    validations = _context_validation(lines, idx)
    validated = bool(validations)
    notes: List[str] = []

    if _arg_is_literal(arg) and not taint_hits:
        return Severity.LOW, False, validated, "static URL literal; low SSRF risk", notes

    tainted = bool(taint_hits)
    if tainted:
        notes.append("taint hints: " + ", ".join(sorted(set(taint_hits))[:6]))

    if tainted and not validated:
        return Severity.HIGH, True, False, "attacker-influenced URL reaches fetch with no nearby validation", notes
    if tainted and validated:
        notes.append("validation tokens nearby: " + ", ".join(sorted(set(validations))[:4]))
        return Severity.MEDIUM, True, True, "tainted URL but validation appears nearby; verify it blocks internal hosts", notes
    # variable, no obvious taint hint, no literal
    return Severity.MEDIUM, False, validated, "non-literal URL into fetch; confirm source is not user-controlled", notes


def scan_source(source: str, filename: str = "<source>") -> List[Finding]:
    """Scan a single source string and return findings."""
    findings: List[Finding] = []
    lines = source.splitlines()
    for idx, raw in enumerate(lines):
        line = raw
        stripped = line.lstrip()
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
            continue
        for rule_id, rx, label in SINK_RULES:
            m = rx.search(line)
            if not m:
                continue
            arg = m.group(1).strip()
            if not arg:
                continue
            sev, tainted, validated, reason, notes = _classify(arg, lines, idx)
            findings.append(
                Finding(
                    file=filename,
                    line=idx + 1,
                    rule_id=rule_id,
                    sink=label,
                    severity=sev.value,
                    argument=arg[:120],
                    snippet=line.strip()[:200],
                    reason=reason,
                    tainted=tainted,
                    validated_nearby=validated,
                    notes=notes,
                )
            )
    return findings


def _iter_files(path: str) -> Iterable[str]:
    if os.path.isfile(path):
        yield path
        return
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if os.path.splitext(name)[1] in SCAN_EXTS:
                yield os.path.join(root, name)


def scan_path(path: str, min_severity: Optional[str] = None) -> List[Finding]:
    """Scan a file or directory tree and return findings.

    Raises FileNotFoundError if the path does not exist.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    order = {"low": 0, "medium": 1, "high": 2}
    floor = order.get((min_severity or "low").lower(), 0)
    out: List[Finding] = []
    for fp in _iter_files(path):
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                src = fh.read()
        except OSError:
            continue
        for f in scan_source(src, fp):
            if order[f.severity] >= floor:
                out.append(f)
    out.sort(key=lambda f: (-order[f.severity], f.file, f.line))
    return out
