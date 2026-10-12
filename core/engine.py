# core/engine.py
# VANTA 1.0 — Core Engine
# Главный контроллер. Не содержит тяжёлой логики сканирования.

from datetime import datetime
from typing import Callable, Optional, Dict, Any
import threading
import time


class VantaEngine:
    """
    Главный движок VANTA.
    Управляет жизненным циклом сканирования и связывает модули.
    """

    def __init__(self):
        self.target: Optional[str] = None
        self.is_running: bool = False
        self.is_safe_mode: bool = True          # Safe mode по умолчанию

        self.findings: Dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }

        self.modules_status: Dict[str, str] = {
            "http": "IDLE",
            "dns": "IDLE",
            "tls": "IDLE",
            "headers": "IDLE",
            "technology": "IDLE",
            "subdomains": "IDLE"
        }

        # Callbacks для связи с GUI
        self.on_log: Optional[Callable[[str], None]] = None
        self.on_status: Optional[Callable[[str, str], None]] = None
        self.on_finding: Optional[Callable[[str, int], None]] = None
        self.on_activity: Optional[Callable[[int], None]] = None
        self.on_finished: Optional[Callable[[], None]] = None

        self._scan_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    # ---------------------------------------------------------
    # Публичные методы
    # ---------------------------------------------------------

    def set_target(self, target: str) -> bool:
        """Устанавливает цель сканирования"""
        target = target.strip()
        if not target:
            self._log("ERROR: target is empty")
            return False

        self.target = target
        self._log(f"Target set: {target}")
        return True

    def start(self) -> bool:
        """Запускает сканирование в отдельном потоке"""
        if self.is_running:
            self._log("WARNING: scan already running")
            return False

        if not self.target:
            self._log("ERROR: no target specified")
            return False

        self.is_running = True
        self._stop_event.clear()
        self._reset_findings()

        self._log("=" * 50)
        self._log(f"VANTA SCAN STARTED → {self.target}")
        self._log(f"Safe mode: {'ON' if self.is_safe_mode else 'OFF'}")
        self._log("=" * 50)

        self._set_status("● SCANNING", "#20ff9a")

        self._scan_thread = threading.Thread(
            target=self._run_scan,
            daemon=True
        )
        self._scan_thread.start()
        return True

    def stop(self):
        """Останавливает сканирование"""
        if not self.is_running:
            self._log("INFO: no active scan")
            return

        self._stop_event.set()
        self.is_running = False
        self._log("Scan stop requested by user...")
        self._set_status("● STOPPING", "#ff8a20")

    def clear_findings(self):
        """Сбрасывает счётчики находок"""
        self._reset_findings()
        self._log("Findings cleared")

    # ---------------------------------------------------------
    # Внутренняя логика
    # ---------------------------------------------------------

    def _run_scan(self):
        """Основной цикл сканирования (заглушка)"""
        try:
            modules = [
                ("dns", "DNS analysis"),
                ("http", "HTTP/HTTPS check"),
                ("tls", "TLS/SSL analysis"),
                ("headers", "Security headers"),
                ("technology", "Technology detection"),
                ("subdomains", "Subdomain discovery"),
            ]

            for module_name, description in modules:
                if self._stop_event.is_set():
                    break

                self.modules_status[module_name] = "RUNNING"
                self._log(f"[+] Starting module: {description}")
                self._set_activity(random_activity=True)

                # Имитация работы модуля (потом заменим на реальные)
                time.sleep(1.2)

                if self._stop_event.is_set():
                    break

                self.modules_status[module_name] = "DONE"
                self._log(f"[✓] Module finished: {description}")

                # Пример добавления находки (для теста)
                if module_name == "headers":
                    self._add_finding("MEDIUM")
                    self._log("  → Missing security header detected (example)")

            if self._stop_event.is_set():
                self._log("Scan stopped by user")
                self._set_status("● STOPPED", "#ff8a20")
            else:
                self._log("=" * 50)
                self._log("SCAN COMPLETED")
                self._log("=" * 50)
                self._set_status("● COMPLETED", "#20ff9a")

        except Exception as e:
            self._log(f"CRITICAL ERROR in engine: {e}")
            self._set_status("● ERROR", "#ff3030")

        finally:
            self.is_running = False
            if self.on_finished:
                self.on_finished()

    def _reset_findings(self):
        for key in self.findings:
            self.findings[key] = 0
            if self.on_finding:
                self.on_finding(key, 0)

    def _add_finding(self, severity: str):
        if severity in self.findings:
            self.findings[severity] += 1
            if self.on_finding:
                self.on_finding(severity, self.findings[severity])

    def _log(self, message: str):
        if self.on_log:
            self.on_log(message)

    def _set_status(self, text: str, color: str):
        if self.on_status:
            self.on_status(text, color)

    def _set_activity(self, value: int = 0, random_activity: bool = False):
        if self.on_activity:
            if random_activity:
                import random
                value = random.randint(15, 85)
            self.on_activity(value)