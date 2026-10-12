# modules/headers.py

import urllib.request
import ssl


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]


def scan(target, findings, log):
    log(f"  → Analyzing security headers...")

    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            target.url,
            headers={"User-Agent": "VANTA-Security-Auditor/1.0"}
        )
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}

            for h in SECURITY_HEADERS:
                if h.lower() not in headers:
                    findings.add("MEDIUM", f"Missing header: {h}", f"{h} not found", "headers")
                    log(f"  → Missing: {h}")
                else:
                    log(f"  → Found: {h}")

    except Exception as e:
        log(f"  → Headers error: {e}")