# Demo 01 - Basic SSRF triage

This demo runs SSRFIND against a small, deliberately vulnerable web handler
(`webhook_proxy.py`) that mixes a safe static fetch with several SSRF-prone
sinks. It demonstrates the three severity tiers SSRFIND assigns.

## Run it

```bash
python -m ssrfind scan demos/01-basic/webhook_proxy.py
python -m ssrfind scan demos/01-basic/webhook_proxy.py --format json
python -m ssrfind scan demos/01-basic/webhook_proxy.py --min-severity high
```

## What you should see

- **HIGH** - `requests.get(user_url)` and the f-string `urlopen` build a URL
  directly from `request.args` / `request.json` with no validation. These are
  classic SSRF: an attacker can point them at `http://169.254.169.254/` (cloud
  metadata) or internal services.
- **MEDIUM** - the fetch that runs `urlparse`/allowlist nearby is downgraded
  because validation *appears* present; a reviewer must confirm it actually
  blocks private/link-local ranges.
- **LOW** - `requests.get("https://status.example.com/health")` is a static
  literal with no taint, so it is reported only as informational context.

Exit code is non-zero whenever findings are reported, so this is CI-friendly.

## Remediation guidance (not performed by the tool)

1. Resolve the host and reject RFC1918 / link-local / loopback addresses.
2. Enforce an explicit allow-list of destination hosts.
3. Disable redirects or re-validate each redirect target.
4. Use a dedicated egress proxy with deny rules for internal CIDRs.
