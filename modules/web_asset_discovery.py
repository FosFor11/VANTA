# modules/web_asset_discovery.py
# VANTA 1.1 — Web asset discovery (passive)

import urllib.request
import ssl
import re

INTERESTING_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/.well-known/security.txt",
    "/security.txt",
    "/manifest.json",
    "/favicon.ico",
    "/humans.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
]


def scan(target, findings, log):
    log("  → Web asset discovery...")

    ctx = ssl.create_default_context()
    headers = {"User-Agent": "VANTA-Security-Auditor/1.0"}
    found_assets = []
    api_hints = set()

    for path in INTERESTING_PATHS:
        url = f"{target.scheme}://{target.domain}{path}"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                if resp.getcode() == 200:
                    found_assets.append(path)
                    log(f"  → Found asset: {path}")

                    content_type = resp.headers.get("content-type", "").lower()
                    body = resp.read(15000).decode("utf-8", errors="ignore")

                    # Ищем возможные API-пути в содержимом
                    if any(x in content_type for x in ["javascript", "json", "text", "xml", "html"]):
                        pattern = r'["\'](/api/[^"\'\s]+|/graphql|/auth[^"\'\s]*|/oauth[^"\'\s]*)["\']'
                        for match in re.findall(pattern, body):
                            api_hints.add(match)
        except Exception:
            pass

    if found_assets:
        findings.add("INFO", "Discovered web assets", ", ".join(found_assets), "web_asset_discovery")

    if api_hints:
        limited = list(api_hints)[:10]
        findings.add("MEDIUM", "Possible API endpoints in assets", ", ".join(limited), "web_asset_discovery")
        log(f"  → API hints: {', '.join(limited)}")