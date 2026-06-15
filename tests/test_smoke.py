"""Smoke tests for SSRFIND. No network access is performed."""
import json
import os
import subprocess
import sys

import pytest

import ssrfind
from ssrfind.cli import main
from ssrfind.core import scan_source, scan_path, scan, to_json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, "demos", "01-basic", "webhook_proxy.py")


def test_exports():
    assert ssrfind.TOOL_NAME == "ssrfind"
    assert isinstance(ssrfind.TOOL_VERSION, str) and ssrfind.TOOL_VERSION


def test_tainted_fetch_is_high():
    src = (
        "import requests\n"
        "def view(request):\n"
        "    user_url = request.args.get('url')\n"
        "    return requests.get(user_url)\n"
    )
    findings = scan_source(src, "v.py")
    assert any(f.severity == "high" and f.tainted for f in findings)


def test_static_literal_is_low():
    src = 'import requests\nrequests.get("https://example.com/health")\n'
    findings = scan_source(src, "lit.py")
    assert findings
    assert all(f.severity == "low" for f in findings)


def test_validation_nearby_downgrades_to_medium():
    src = (
        "import requests\n"
        "from urllib.parse import urlparse\n"
        "def view(request):\n"
        "    target = request.args.get('target')\n"
        "    parsed = urlparse(target)\n"
        "    if parsed.hostname not in ALLOWED_HOSTS:\n"
        "        raise Exception('blocked')\n"
        "    return requests.get(target)\n"
    )
    findings = scan_source(src, "safe.py")
    sinks = [f for f in findings if f.rule_id == "py.requests"]
    assert sinks and any(f.severity == "medium" and f.validated_nearby for f in sinks)


def test_js_fetch_detected():
    src = "const r = await fetch(req.query.target);\n"
    findings = scan_source(src, "app.js")
    assert any(f.rule_id == "js.fetch" and f.severity == "high" for f in findings)


def test_scan_path_on_demo_file():
    findings = scan_path(DEMO)
    assert any(f.severity == "high" for f in findings)
    assert any(f.severity == "low" for f in findings)


def test_scan_path_missing_raises():
    try:
        scan_path(os.path.join(ROOT, "does-not-exist-xyz"))
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("expected FileNotFoundError")


def test_min_severity_filter():
    all_f = scan_path(DEMO, min_severity="low")
    high_only = scan_path(DEMO, min_severity="high")
    assert len(high_only) <= len(all_f)
    assert all(f.severity == "high" for f in high_only)


def test_cli_json_and_exit_code():
    rc = main(["scan", DEMO, "--format", "json"])
    assert rc == 1  # findings present -> non-zero


def test_cli_no_findings_exit_zero(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text("x = 1 + 1\nprint('hello')\n")
    rc = main(["scan", str(clean)])
    assert rc == 0


def test_cli_missing_path_exit_two():
    rc = main(["scan", os.path.join(ROOT, "nope-nope-nope")])
    assert rc == 2


def test_cli_subprocess_json_parses():
    proc = subprocess.run(
        [sys.executable, "-m", "ssrfind", "scan", DEMO, "--format", "json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    data = json.loads(proc.stdout)
    assert data["tool"] == "ssrfind"
    assert data["summary"]["high"] >= 1


# ---------------------------------------------------------------------------
# Hardening tests: edge cases and error paths
# ---------------------------------------------------------------------------


def test_scan_source_empty_returns_no_findings():
    """Empty source string must return an empty list, not raise."""
    assert scan_source("") == []


def test_scan_source_comment_only_returns_no_findings():
    """Lines that are pure comments must not produce findings."""
    src = "# requests.get(user_url)\n// fetch(req.query.url)\n"
    assert scan_source(src, "commented.py") == []


def test_scan_source_wrong_type_raises():
    """Passing a non-string to scan_source must raise TypeError."""
    with pytest.raises(TypeError):
        scan_source(None)  # type: ignore[arg-type]


def test_scan_path_invalid_min_severity_raises():
    """An unknown min_severity value must raise ValueError, not silently pass."""
    with pytest.raises(ValueError, match="min_severity"):
        scan_path(DEMO, min_severity="critical")


def test_to_json_produces_valid_json():
    """to_json must return a valid JSON string with expected schema keys."""
    src = 'requests.get(user_input)\n'
    findings = scan_source(src, "t.py")
    result = to_json(findings, scanned="t.py")
    data = json.loads(result)
    assert "tool" in data
    assert "summary" in data
    assert "findings" in data
    assert data["summary"]["total"] == len(findings)


def test_scan_alias_matches_scan_path():
    """scan() must return the same results as scan_path() for an existing file."""
    via_alias = scan(DEMO)
    via_scan_path = scan_path(DEMO)
    assert [f.to_dict() for f in via_alias] == [f.to_dict() for f in via_scan_path]


def test_cli_no_subcommand_returns_exit_two():
    """Calling main() with no subcommand must print help and return 2."""
    rc = main([])
    assert rc == 2
