# modules/service_fingerprint.py
# VANTA 1.1 — Light service fingerprinting (banner grabbing)

import socket
import re

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    2082: "cPanel",
    2083: "cPanel-SSL",
    2086: "WHM",
    2087: "WHM-SSL",
}

def grab_banner(host, port, timeout=2.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Для некоторых служб нужно немного "поздороваться"
        if port in (21, 25, 110, 143):
            banner = sock.recv(1024)
        elif port == 22:
            banner = sock.recv(1024)
        elif port == 3306:
            banner = sock.recv(1024)
        else:
            # Для HTTP просто пробуем прочитать
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024)

        sock.close()
        return banner.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""

def detect_service(port, banner):
    banner_l = banner.lower()

    if port == 21 or "ftp" in banner_l:
        ver = re.search(r"vsftpd\s*([\d.]+)", banner, re.I)
        if ver:
            return "FTP", f"vsftpd {ver.group(1)}"
        if "pure-ftpd" in banner_l:
            return "FTP", "Pure-FTPd"
        return "FTP", banner[:60] if banner else "FTP"

    if port == 22 or banner.startswith("SSH-"):
        ver = re.search(r"OpenSSH[_\s-]*([\d.p]+)", banner, re.I)
        if ver:
            return "SSH", f"OpenSSH {ver.group(1)}"
        return "SSH", banner[:60] if banner else "SSH"

    if port == 25 or "smtp" in banner_l or "esmtp" in banner_l:
        if "postfix" in banner_l:
            return "SMTP", "Postfix"
        if "exim" in banner_l:
            return "SMTP", "Exim"
        return "SMTP", banner[:60] if banner else "SMTP"

    if port in (110, 143) or "dovecot" in banner_l:
        return "Mail", "Dovecot" if "dovecot" in banner_l else banner[:50]

    if port == 3306 or "mysql" in banner_l:
        ver = re.search(r"([\d.]+)-?", banner)
        if ver:
            return "MySQL", f"MySQL {ver.group(1)}"
        return "MySQL", "MySQL"

    if port in (80, 443, 8080, 8443):
        if "nginx" in banner_l:
            return "HTTP", "nginx"
        if "apache" in banner_l:
            return "HTTP", "Apache"
        return "HTTP", "HTTP"

    if port in (2082, 2083, 2086, 2087):
        return "cPanel", "cPanel/WHM"

    return COMMON_PORTS.get(port, "Unknown"), banner[:50] if banner else ""

def scan(target, findings, log):
    log("  → Service fingerprinting (light)...")

    host = target.domain
    results = []

    for port, default_name in COMMON_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        try:
            if sock.connect_ex((host, port)) == 0:
                banner = grab_banner(host, port)
                service, version = detect_service(port, banner)
                line = f"{port}/tcp → {service} → {version}"
                results.append(line)
                log(f"  → {line}")
        except Exception:
            pass
        finally:
            sock.close()

    if results:
        findings.add("INFO", "Service fingerprint", " | ".join(results), "service_fingerprint")

        # Отдельно отмечаем опасные
        risky = [r for r in results if "MySQL" in r or "FTP" in r]
        if risky:
            findings.add("MEDIUM", "Risky services exposed", " | ".join(risky), "service_fingerprint")