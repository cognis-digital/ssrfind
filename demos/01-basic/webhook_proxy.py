"""Deliberately vulnerable demo handler for SSRFIND (NOT for production use).

This mimics a webhook/proxy endpoint. SSRFIND should flag the user-controlled
fetches as high severity and leave the static health check as low.
"""
import urllib.request

import requests
from flask import Flask, request

app = Flask(__name__)

ALLOWED_HOSTS = {"api.partner.example.com"}


@app.route("/proxy")
def proxy():
    # HIGH: URL taken straight from the query string, no validation.
    user_url = request.args.get("url")
    resp = requests.get(user_url, timeout=5)
    return resp.text


@app.route("/fetch-metadata")
def fetch_metadata():
    # HIGH: f-string built from user input feeds urlopen directly.
    host = request.json["host"]
    return urllib.request.urlopen(f"http://{host}/latest/meta-data/").read()


@app.route("/safe-proxy")
def safe_proxy():
    # MEDIUM: validation appears nearby (allowlist + urlparse), verify it works.
    from urllib.parse import urlparse

    target = request.args.get("target")
    parsed = urlparse(target)
    if parsed.hostname not in ALLOWED_HOSTS:
        return "forbidden", 403
    return requests.get(target, timeout=5).text


@app.route("/health")
def health():
    # LOW: static literal, not SSRF-prone.
    return requests.get("https://status.example.com/health", timeout=5).text
