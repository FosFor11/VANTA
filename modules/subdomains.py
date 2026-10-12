# modules/subdomains.py
# Простой и безопасный модуль (только базовые имена)

COMMON = ["www", "mail", "ftp", "admin", "dev", "test", "api", "blog", "shop"]


def scan(target, findings, log):
    log(f"  → Basic subdomain check (passive)...")

    found = []
    for sub in COMMON:
        host = f"{sub}.{target.domain}"
        try:
            import socket
            socket.gethostbyname(host)
            found.append(host)
            log(f"  → Found: {host}")
        except:
            pass

    if found:
        findings.add("INFO", "Subdomains found", ", ".join(found), "subdomains")
    else:
        log("  → No common subdomains found")