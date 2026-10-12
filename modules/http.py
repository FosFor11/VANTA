# modules/http.py

import urllib.request
import ssl


def scan(target, findings, log):
    log(f"  → Checking HTTP/HTTPS connectivity...")

    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            target.url,
            headers={"User-Agent": "VANTA-Security-Auditor/1.0"}
        )
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            code = resp.getcode()
            log(f"  → HTTP status: {code}")

            if code >= 500:
                findings.add("HIGH", f"Server Error {code}", f"Target returned {code}", "http")
            elif code >= 400:
                findings.add("MEDIUM", f"Client Error {code}", f"Target returned {code}", "http")
            else:
                findings.add("INFO", f"HTTP {code}", "Target is reachable", "http")

    except Exception as e:
        findings.add("HIGH", "Connection failed", str(e), "http")
        log(f"  → Connection error: {e}")