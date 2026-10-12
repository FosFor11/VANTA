# modules/cookies.py

import urllib.request
import ssl
import http.cookiejar


def scan(target, findings, log):
    log("  → Checking cookie flags...")

    try:
        ctx = ssl.create_default_context()
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar),
            urllib.request.HTTPSHandler(context=ctx)
        )
        req = urllib.request.Request(
            target.url,
            headers={"User-Agent": "VANTA-Security-Auditor/1.0"}
        )
        opener.open(req, timeout=8)

        if not jar:
            log("  → No cookies set")
            findings.add("INFO", "No cookies", "Server did not set cookies", "cookies")
            return

        for cookie in jar:
            issues = []
            if not cookie.get_nonstandard_attr("httponly", False) and not getattr(cookie, "has_nonstandard_attr", lambda x: False)("HttpOnly"):
                # Простая проверка
                pass

            # Более надёжный способ — смотрим заголовок Set-Cookie
            log(f"  → Cookie found: {cookie.name}")

        # Дополнительно читаем сырые заголовки
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            set_cookie = resp.headers.get_all("Set-Cookie") or []
            for raw in set_cookie:
                raw_l = raw.lower()
                name = raw.split("=")[0]
                log(f"  → Analyzing cookie: {name}")

                if "httponly" not in raw_l:
                    findings.add("MEDIUM", f"Cookie without HttpOnly: {name}", "Missing HttpOnly flag", "cookies")
                if "secure" not in raw_l and target.scheme == "https":
                    findings.add("MEDIUM", f"Cookie without Secure: {name}", "Missing Secure flag", "cookies")
                if "samesite" not in raw_l:
                    findings.add("LOW", f"Cookie without SameSite: {name}", "Missing SameSite attribute", "cookies")

    except Exception as e:
        log(f"  → Cookies check error: {e}")