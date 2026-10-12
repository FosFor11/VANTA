# modules/http_behavior.py
# VANTA 1.1 — HTTP behavior analysis (real endpoint vs fallback)

import urllib.request
import ssl
import hashlib

def get_response(url, ctx, headers):
    try:
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=6, context=ctx) as resp:
            body = resp.read(8192)
            return {
                "code": resp.getcode(),
                "headers": dict(resp.headers),
                "length": len(body),
                "hash": hashlib.md5(body).hexdigest()[:12],
                "title": extract_title(body)
            }
    except Exception as e:
        return {"code": 0, "error": str(e)}

def extract_title(body):
    try:
        text = body.decode("utf-8", errors="ignore")
        start = text.lower().find("<title>")
        if start == -1:
            return ""
        end = text.lower().find("</title>", start)
        return text[start+7:end].strip()[:60]
    except:
        return ""

def scan(target, findings, log):
    log("  → HTTP behavior analysis...")

    ctx = ssl.create_default_context()
    headers = {"User-Agent": "VANTA-Security-Auditor/1.0"}

    paths = [
        "/",
        "/admin",
        "/admin/",
        "/ADMIN",
        "/login",
        "/wp-admin",
        "/wp-login.php",
        "/nonexistent-vanta-404-test-page-12345"
    ]

    results = {}
    for path in paths:
        url = f"{target.scheme}://{target.domain}{path}"
        results[path] = get_response(url, ctx, headers)
        code = results[path].get("code", 0)
        log(f"  → {path} → {code}")

    # Анализ
    not_found = results.get("/nonexistent-vanta-404-test-page-12345", {})
    baseline_hash = not_found.get("hash")
    baseline_code = not_found.get("code")

    real_endpoints = []
    for path, data in results.items():
        if path.startswith("/nonexistent"):
            continue
        if data.get("code") in (200, 301, 302, 401, 403):
            # Если ответ сильно отличается от 404-страницы — скорее реальный
            if data.get("hash") != baseline_hash or data.get("code") != baseline_code:
                real_endpoints.append(f"{path} [{data.get('code')}]")

    if real_endpoints:
        findings.add("MEDIUM", "Interesting HTTP endpoints", ", ".join(real_endpoints), "http_behavior")
        log(f"  → Real/interesting endpoints: {len(real_endpoints)}")
    else:
        log("  → No strongly distinctive endpoints found")