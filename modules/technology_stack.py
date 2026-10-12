# modules/technology_stack.py
# VANTA 1.1 — Technology stack detection with confidence

import urllib.request
import ssl
import re

def scan(target, findings, log):
    log("  → Technology stack detection...")

    ctx = ssl.create_default_context()
    headers = {"User-Agent": "VANTA-Security-Auditor/1.0"}
    stack = []

    try:
        req = urllib.request.Request(target.url, headers=headers)
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read(12000).decode("utf-8", errors="ignore")

            # Server
            server = hdrs.get("server", "")
            if "nginx" in server.lower():
                stack.append(("Web Server", "nginx", 90))
            elif "apache" in server.lower():
                stack.append(("Web Server", "Apache", 90))
            elif server:
                stack.append(("Web Server", server, 70))

            # Language / Runtime
            powered = hdrs.get("x-powered-by", "")
            if "php" in powered.lower():
                ver = re.search(r"PHP/([\d.]+)", powered, re.I)
                name = f"PHP {ver.group(1)}" if ver else "PHP"
                stack.append(("Runtime", name, 95))
            if "asp.net" in powered.lower() or "x-aspnet" in str(hdrs):
                stack.append(("Framework", "ASP.NET", 85))

            # CMS
            if "wp-content" in body or "wordpress" in body.lower() or "/wp-json" in body:
                stack.append(("CMS", "WordPress", 92))
            if "joomla" in body.lower():
                stack.append(("CMS", "Joomla", 80))
            if "drupal" in body.lower():
                stack.append(("CMS", "Drupal", 80))

            # JS frameworks
            if "react" in body.lower() or "reactdom" in body.lower():
                stack.append(("JS", "React", 75))
            if "vue" in body.lower():
                stack.append(("JS", "Vue.js", 70))
            if "angular" in body.lower():
                stack.append(("JS", "Angular", 70))

            # CDN / WAF hints
            if "cf-ray" in hdrs or "cloudflare" in str(hdrs).lower():
                stack.append(("CDN/WAF", "Cloudflare", 90))
            if "x-sucuri" in hdrs:
                stack.append(("WAF", "Sucuri", 85))

            # Cookies hints
            set_cookie = str(hdrs.get("set-cookie", "")).lower()
            if "wordpress" in set_cookie or "wp-" in set_cookie:
                stack.append(("CMS", "WordPress (cookie)", 80))

    except Exception as e:
        log(f"  → Technology detection error: {e}")
        return

    if stack:
        summary = []
        for category, name, conf in stack:
            summary.append(f"{name} ({conf}%)")
            log(f"  → {category}: {name}  [confidence {conf}%]")
        findings.add("INFO", "Technology stack", " | ".join(summary), "technology_stack")
    else:
        log("  → No clear technology signatures found")