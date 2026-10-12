# reports/txt.py

from pathlib import Path
from datetime import datetime


def save_txt(target, findings_manager, log):
    desktop = Path.home() / "Desktop"
    if not desktop.exists():
        desktop = Path.home() / "Рабочий стол"
    if not desktop.exists():
        desktop = Path.home()

    filename = desktop / f"VANTA_Report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("          VANTA 1.0 — WEB SECURITY REPORT\n")
        f.write("=" * 70 + "\n")
        f.write(f"Target     : {target}\n")
        f.write(f"Date       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")

        counts = findings_manager.get_counts()
        f.write("SUMMARY\n")
        f.write("-" * 40 + "\n")
        for sev, cnt in counts.items():
            f.write(f"{sev:10}: {cnt}\n")

        f.write("\nFINDINGS\n")
        f.write("-" * 40 + "\n")
        for item in findings_manager.get_all():
            f.write(f"[{item.severity}] {item.title}\n")
            f.write(f"    {item.description}\n")
            f.write(f"    Module: {item.module} | {item.timestamp}\n\n")

    log(f"TXT report saved → {filename}")
    return str(filename)