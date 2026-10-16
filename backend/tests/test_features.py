from datetime import datetime

import pytest

from settings import SystemSettings
from test_system import env, login, upload, drain  # noqa: F401  (fixture re-use)


# ---------------------------------------------------------------- schedule logic
def test_schedule_overnight_window(tmp_path):
    s = SystemSettings(tmp_path / "s.json")
    s.update({"schedule": {"enabled": True, "start": "20:00", "end": "06:00", "days": [0]}})  # Monday nights
    mon_21 = datetime(2026, 10, 12, 21, 0)    # Monday 21:00 -> armed
    tue_03 = datetime(2026, 10, 13, 3, 0)     # Tuesday 03:00 belongs to Monday's window -> armed
    tue_21 = datetime(2026, 10, 13, 21, 0)    # Tuesday night not scheduled
    mon_12 = datetime(2026, 10, 12, 12, 0)    # daytime
    assert s.status(mon_21)["armed"] and s.status(tue_03)["armed"]
    assert not s.status(tue_21)["armed"] and not s.status(mon_12)["armed"]


def test_schedule_validation_and_persistence(tmp_path):
    s = SystemSettings(tmp_path / "s.json")
    for bad in ({"armed": "yes"}, {"schedule": {"start": "25:00"}}, {"schedule": {"days": []}},
                {"schedule": {"start": "08:00", "end": "08:00"}}):
        with pytest.raises(ValueError):
            s.update(bad)
    s.update({"armed": False})
    assert SystemSettings(tmp_path / "s.json").status()["armed"] is False
    assert SystemSettings(tmp_path / "s.json").status()["reason"] == "Disarmed manually"


# ---------------------------------------------------------------- API
def test_disarmed_system_raises_no_incident(env):
    app, client, det, ledger, ext = env
    det.boxes = [(400, 100, 480, 400)]
    ext["settings"].update({"armed": False})
    r = upload(client).get_json()
    assert r["intruders"] == 1 and r["armed"] is False and r["incident"] is None
    ext["settings"].update({"armed": True})
    assert upload(client).get_json()["incident"]


def test_settings_api_admin_only(env):
    app, client, *_ = env
    _, token = login(client, "guard", "guard-password")
    assert client.get("/api/settings").status_code == 200
    assert client.post("/api/settings", json={"armed": False},
                       headers={"X-CSRF-Token": token}).status_code == 403
    c2 = app.test_client(); c2.environ_base["wsgi.url_scheme"] = "https"
    _, at = login(c2, "admin", "admin-password")
    r = c2.post("/api/settings", json={"armed": False}, headers={"X-CSRF-Token": at})
    assert r.status_code == 200 and r.get_json()["armed"] is False
    r = c2.post("/api/settings", json={"schedule": {"start": "99:00"}}, headers={"X-CSRF-Token": at})
    assert r.status_code == 400


def test_alerts_analytics_exports_and_ack_all(env):
    app, client, det, ledger, ext = env
    det.boxes = [(400, 100, 480, 400)]
    inc_id = upload(client).get_json()["incident"]
    drain(ext)
    _, token = login(client, "guard", "guard-password")

    a = client.get("/api/alerts").get_json()
    assert a["latest"]["id"] == inc_id and a["open"] == 1 and a["arm"]["armed"] is True

    an = client.get("/api/analytics?days=7").get_json()
    assert an["summary"]["total"] == 1 and sum(an["hourly"].values()) == 1
    assert an["cameras"][0]["camera_id"] == "cam-01"

    csv = client.get("/export/incidents.csv?status=open")
    assert csv.status_code == 200 and inc_id in csv.get_data(as_text=True)
    assert inc_id not in client.get("/export/incidents.csv?status=acknowledged").get_data(as_text=True)

    pdf = client.get(f"/incident/{inc_id}/report.pdf")
    assert pdf.status_code == 200 and pdf.data[:5] == b"%PDF-" and len(pdf.data) > 5000

    found = client.get(f"/api/incidents/search?q={inc_id[-6:]}").get_json()["incidents"]
    assert [i["id"] for i in found] == [inc_id]

    r = client.post("/api/incidents/ack-all", headers={"X-CSRF-Token": token}).get_json()
    assert r["acknowledged"] == 1 and client.get("/api/alerts").get_json()["open"] == 0


def test_all_pages_render(env):
    app, client, *_ = env
    login(client, "admin", "admin-password")
    for path in ["/", "/live", "/incidents", "/analytics", "/settings", "/zone", "/users"]:
        assert client.get(path).status_code == 200, path
