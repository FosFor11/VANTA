# reports/json.py

import json
from pathlib import Path
from datetime import datetime


def save_json(target, findings_manager, log):
    desktop = Path.home() / "Desktop"
    if not desktop.exists():
        desktop = Path.home() / "Рабочий стол"
    if not desktop.exists():
        desktop = Path.home()

    filename = desktop / f"VANTA_Report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.json"

    data = {
        "target": str(target),
        "date": datetime.now().isoformat(),
        "summary": findings_manager.get_counts(),
        "findings": [
            {
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "module": f.module,
                "timestamp": f.timestamp
            }
            for f in findings_manager.get_all()
        ]
    }

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    log(f"JSON report saved → {filename}")
    return str(filename)