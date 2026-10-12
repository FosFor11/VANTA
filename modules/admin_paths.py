# modules/admin_paths.py
# Поиск типичных страниц входа и админки (только проверка существования)

import urllib.request
import ssl

# Список самых распространённых путей
COMMON_PATHS = [
    "/admin",
    "/admin/",
    "/administrator",
    "/administrator/",
    "/wp-admin",
    "/wp-admin/",
    "/wp-login.php",
    "/login",
    "/login/",
    "/user/login",
    "/admin/login",
    "/admin/login.php",
    "/administrator/index.php",
    "/panel",
    "/cpanel",
    "/manager",
    "/backend",
    "/dashboard",
    "/admin.php",
    "/login.php",
    "/user",
    "/account",
    "/signin",
    "/auth",
]


def scan(target, findings, log):
    log("  → Searching for common admin / login pages...")

    ctx = ssl.create_default_context()
    headers = {"User-Agent": "VANTA-Security-Auditor/1.0"}
    found = []

    for path in COMMON_PATHS:
        url = f"{target.scheme}://{target.domain}{path}"
        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                code = resp.getcode()
                if code in (200, 301, 302, 401, 403):
                    found.append(f"{path} [{code}]")
                    log(f"  → Found: {path} (HTTP {code})")
        except Exception:
            # 404 и другие ошибки просто пропускаем
            pass

    if found:
        findings.add(
            "MEDIUM",
            "Possible admin/login pages found",
            ", ".join(found),
            "admin_paths"
        )
        log(f"  → Total found: {len(found)}")
    else:
        log("  → No common admin pages found")