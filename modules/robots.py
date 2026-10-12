# modules/robots.py

import urllib.request
import ssl


def scan(target, findings, log):
    log("  → Checking robots.txt and sitemap...")

    ctx = ssl.create_default_context()
    headers = {"User-Agent": "VANTA-Security-Auditor/1.0"}

    # robots.txt
    try:
        robots_url = f"{target.scheme}://{target.domain}/robots.txt"
        req = urllib.request.Request(robots_url, headers=headers)
        with urllib.request.urlopen(req, timeout=6, context=ctx) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            log("  → robots.txt found")
            findings.add("INFO", "robots.txt present", "File is accessible", "robots")

            if "Disallow: /" in content:
                findings.add("INFO", "robots.txt Disallow", "Root path is disallowed", "robots")
    except Exception:
        log("  → robots.txt not found or inaccessible")

    # sitemap
    for path in ["/sitemap.xml", "/sitemap_index.xml"]:
        try:
            sitemap_url = f"{target.scheme}://{target.domain}{path}"
            req = urllib.request.Request(sitemap_url, headers=headers)
            with urllib.request.urlopen(req, timeout=6, context=ctx) as resp:
                if resp.getcode() == 200:
                    log(f"  → Found: {path}")
                    findings.add("INFO", f"Sitemap found: {path}", "Sitemap is accessible", "robots")
                    break
        except Exception:
            pass