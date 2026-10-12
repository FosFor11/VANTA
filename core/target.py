# core/target.py
# VANTA 1.0 — Target parser & validator

from urllib.parse import urlparse
import re
import socket


class Target:
    """Разбор и проверка цели (URL / домен / IP)"""

    def __init__(self, raw: str):
        self.raw = raw.strip()
        self.url = None
        self.domain = None
        self.ip = None
        self.scheme = "https"
        self.port = 443
        self.is_valid = False
        self.error = None

        self._parse()

    def _parse(self):
        if not self.raw:
            self.error = "Empty target"
            return

        text = self.raw

        # Если пользователь ввёл просто IP
        if self._is_ip(text):
            self.ip = text
            self.domain = text
            self.url = f"https://{text}"
            self.is_valid = True
            return

        # Если нет схемы — добавляем https
        if not text.startswith(("http://", "https://")):
            text = "https://" + text

        try:
            parsed = urlparse(text)
            self.scheme = parsed.scheme or "https"
            self.domain = parsed.hostname
            self.port = parsed.port or (443 if self.scheme == "https" else 80)
            self.url = f"{self.scheme}://{self.domain}"
            if parsed.port:
                self.url += f":{parsed.port}"

            if not self.domain:
                self.error = "Invalid domain"
                return

            self.is_valid = True

        except Exception as e:
            self.error = str(e)

    def _is_ip(self, value: str) -> bool:
        try:
            socket.inet_aton(value)
            return True
        except:
            return False

    def __str__(self):
        return self.url or self.raw