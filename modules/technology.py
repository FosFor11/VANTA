# modules/technology.py

import urllib.request
import ssl
import re


def scan(target, findings, log):
    log(f"  → Detecting technologies...")

    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            target.url,
            headers={"User-Agent": "VANTA-Security-Auditor/1.0"}
        )
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            server = resp.headers.get("Server", "Unknown")
            powered = resp.headers.get("X-Powered-By", "")
            body = resp.read(4096).decode("utf-8", errors="ignore")

            log(f"  → Server: {server}")
            findings.add("INFO", "Server header", server, "technology")

            if powered:
                log(f"  → X-Powered-By: {powered}")
                findings.add("INFO", "X-Powered-By", powered, "technology")

            # Простые сигнатуры
            if "wp-content" in body or "wordpress" in body.lower():
                findings.add("INFO", "WordPress detected", "Possible WordPress", "technology")
                log("  → Technology: WordPress")

    except Exception as e:
        log(f"  → Technology error: {e}")