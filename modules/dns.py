# modules/dns.py

import socket


def scan(target, findings, log):
    log(f"  → Resolving DNS for {target.domain}...")

    try:
        ip = socket.gethostbyname(target.domain)
        log(f"  → Resolved to {ip}")
        findings.add("INFO", "DNS Resolved", f"{target.domain} → {ip}", "dns")
    except Exception as e:
        findings.add("MEDIUM", "DNS Resolution failed", str(e), "dns")
        log(f"  → DNS error: {e}")