
        # modules/tls.py

import ssl
import socket
from datetime import datetime


def scan(target, findings, log):
    log("  → Checking TLS/SSL in detail...")

    try:
        context = ssl.create_default_context()
        with socket.create_connection((target.domain, target.port), timeout=7) as sock:
            with context.wrap_socket(sock, server_hostname=target.domain) as ssock:
                version = ssock.version()
                cipher = ssock.cipher()
                cert = ssock.getpeercert()

                log(f"  → TLS version : {version}")
                log(f"  → Cipher      : {cipher[0] if cipher else 'unknown'}")

                findings.add("INFO", f"TLS {version}", f"Cipher: {cipher[0] if cipher else 'n/a'}", "tls")

                if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    findings.add("HIGH", "Weak TLS version", f"Using outdated {version}", "tls")

                # Срок действия сертификата
                if cert and "notAfter" in cert:
                    expire = cert["notAfter"]
                    log(f"  → Certificate expires: {expire}")
                    findings.add("INFO", "Certificate expiration", expire, "tls")

    except Exception as e:
        findings.add("MEDIUM", "TLS check failed", str(e), "tls")
        log(f"  → TLS error: {e}")