# modules/ports.py
# Проверяем только самые распространённые порты (безопасно и быстро)

import socket

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
    8443: "HTTPS-Alt"
}


def scan(target, findings, log):
    log("  → Checking common ports (limited set)...")

    host = target.domain
    open_ports = []
    closed_ports = []

    for port, name in COMMON_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.2)
        try:
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(f"{port}/{name}")
                log(f"  → Port {port} ({name}) — OPEN")
            else:
                closed_ports.append(str(port))
        except Exception:
            closed_ports.append(str(port))
        finally:
            sock.close()

    if open_ports:
        findings.add("INFO", "Open ports", ", ".join(open_ports), "ports")
    else:
        log("  → No common ports open (or filtered)")

    # Дополнительно отмечаем потенциально опасные
    dangerous = [p for p in open_ports if any(x in p for x in ["21/", "23/", "3389/", "3306/"])]
    if dangerous:
        findings.add("MEDIUM", "Potentially risky open ports", ", ".join(dangerous), "ports")