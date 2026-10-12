# core/scanner.py
# VANTA 1.1 — Scanner orchestrator

from core.target import Target
from core.findings import FindingsManager

from modules import (
    http, dns, tls, headers, technology, subdomains,
    cookies, robots, ports, admin_paths,
    service_fingerprint, http_behavior, technology_stack,
    dns_intelligence, web_asset_discovery
)

import time


class Scanner:
    def __init__(self, target: Target, findings: FindingsManager, log_callback=None):
        self.target = target
        self.findings = findings
        self.log = log_callback or print
        self.should_stop = False

    def stop(self):
        self.should_stop = True

    def run(self):
        if not self.target.is_valid:
            self.log(f"ERROR: Invalid target — {self.target.error}")
            return

        self.log(f"Starting VANTA 1.1 scan for: {self.target}")
        self.log("-" * 55)

        modules = [
            ("DNS", dns.scan),
            ("DNS Intelligence", dns_intelligence.scan),
            ("HTTP", http.scan),
            ("TLS", tls.scan),
            ("Headers", headers.scan),
            ("Cookies", cookies.scan),
            ("Technology", technology.scan),
            ("Technology Stack", technology_stack.scan),
            ("Service Fingerprint", service_fingerprint.scan),
            ("HTTP Behavior", http_behavior.scan),
            ("Web Asset Discovery", web_asset_discovery.scan),
            ("Robots & Sitemap", robots.scan),
            ("Ports", ports.scan),
            ("Subdomains", subdomains.scan),
            ("Admin Paths", admin_paths.scan),
        ]

        for name, func in modules:
            if self.should_stop:
                self.log("Scanner stopped by user")
                break

            self.log(f"[+] Running module: {name}")
            try:
                func(self.target, self.findings, self.log)
            except Exception as e:
                self.log(f"[!] Module {name} error: {e}")

            time.sleep(0.3)

        self.log("-" * 55)
        self.log("[✓] VANTA 1.1 scan finished")