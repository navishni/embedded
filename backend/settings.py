"""Runtime system settings: arm/disarm switch and the armed-hours schedule."""
import json
import re
import threading
from datetime import datetime

_HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")

DEFAULTS = {
    "armed": True,
    "schedule": {
        "enabled": False,
        "start": "20:00",           # local time; may wrap past midnight
        "end": "06:00",
        "days": [0, 1, 2, 3, 4, 5, 6],  # Monday = 0
    },
}


def _minutes(hhmm):
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)


class SystemSettings:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self.data = self._load()

    def _load(self):
        data = json.loads(json.dumps(DEFAULTS))
        try:
            stored = json.loads(self.path.read_text())
            self._validate(stored)
            data.update(stored)
        except (OSError, ValueError, KeyError, TypeError):
            pass
        return data

    @staticmethod
    def _validate(d):
        if not isinstance(d.get("armed"), bool):
            raise ValueError("armed must be true or false")
        s = d.get("schedule")
        if not isinstance(s, dict) or not isinstance(s.get("enabled"), bool):
            raise ValueError("schedule.enabled must be true or false")
        for k in ("start", "end"):
            if not isinstance(s.get(k), str) or not _HHMM.match(s[k]):
                raise ValueError(f"schedule.{k} must be HH:MM (24 h)")
        if s["start"] == s["end"]:
            raise ValueError("schedule start and end must differ")
        days = s.get("days")
        if not isinstance(days, list) or not days or \
                not all(isinstance(x, int) and 0 <= x <= 6 for x in days):
            raise ValueError("schedule.days must list at least one weekday (0-6)")

    def update(self, changes):
        """Merge `changes` (armed and/or schedule) and persist. Raises ValueError."""
        with self._lock:
            new = json.loads(json.dumps(self.data))
            if "armed" in changes:
                new["armed"] = changes["armed"]
            if "schedule" in changes:
                if not isinstance(changes["schedule"], dict):
                    raise ValueError("schedule must be an object")
                new["schedule"].update(changes["schedule"])
                new["schedule"]["days"] = sorted(set(new["schedule"]["days"])) \
                    if isinstance(new["schedule"]["days"], list) else new["schedule"]["days"]
            self._validate(new)
            self.data = new
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(new, indent=2))
            return self.status()

    def status(self, now=None):
        """Return {"armed": effective bool, "reason": str, "settings": raw}."""
        now = now or datetime.now()
        d = self.data
        if not d["armed"]:
            return {"armed": False, "reason": "Disarmed manually", "settings": d}
        s = d["schedule"]
        if not s["enabled"]:
            return {"armed": True, "reason": "Armed 24/7", "settings": d}

        start, end = _minutes(s["start"]), _minutes(s["end"])
        cur = now.hour * 60 + now.minute
        if start < end:
            inside = start <= cur < end
            day = now.weekday()
        else:  # overnight window: belongs to the day it started on
            inside = cur >= start or cur < end
            day = now.weekday() if cur >= start else (now.weekday() - 1) % 7
        if inside and day in s["days"]:
            return {"armed": True, "reason": f"Scheduled {s['start']}-{s['end']}", "settings": d}
        return {"armed": False, "reason": f"Outside schedule ({s['start']}-{s['end']})", "settings": d}
