import base64
import os
import re
import sys
from pathlib import Path

import cv2
import numpy as np
import pytest
from werkzeug.security import generate_password_hash

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app  # noqa: E402
from config import Config  # noqa: E402
from crypto_store import EvidenceStore, EvidenceTampered, sha256_hex  # noqa: E402
from detector import Zone, anchor_point, find_intruders  # noqa: E402

CAM_KEY = "test-camera-key"


def jpeg(w=640, h=480):
    img = np.full((h, w, 3), 80, np.uint8)
    cv2.rectangle(img, (400, 100), (480, 400), (200, 200, 200), -1)
    return cv2.imencode(".jpg", img)[1].tobytes()


class FakeDetector:
    def __init__(self):
        self.boxes = []

    def detect(self, image):
        return [{"box": list(b), "confidence": 0.9} for b in self.boxes]


class FakeLedger:
    def __init__(self):
        self.records = {}

    def record(self, incident_id, ts, cam, h):
        self.records[incident_id] = {"timestamp": ts, "camera_id": cam, "evidence_hash": h,
                                     "recorder": "0xabc", "block_time": ts}
        return "0x" + "11" * 32

    def fetch(self, incident_id):
        return self.records.get(incident_id)


class Silent:
    enabled = False

    def send_intrusion(self, inc):
        return False


@pytest.fixture
def env(tmp_path):
    class Cfg(Config):
        SECRET_KEY = "x" * 32
        DATA_DIR = tmp_path
        DB_PATH = tmp_path / "t.db"
        EVIDENCE_DIR = tmp_path / "evidence"
        ZONE_FILE = tmp_path / "zone.json"
        EVIDENCE_KEY = base64.b64encode(os.urandom(32)).decode()
        CAMERA_KEYS = {"cam-01": CAM_KEY}
        ALERT_COOLDOWN_S = 30

    det, ledger = FakeDetector(), FakeLedger()
    app = create_app(Cfg, detector=det, ledger=ledger, notifier=Silent(), start_worker=False)
    ext = app.extensions["intrusion"]
    ext["db"].add_user("admin", generate_password_hash("admin-password"), "admin")
    ext["db"].add_user("guard", generate_password_hash("guard-password"), "security")
    client = app.test_client()
    client.environ_base["wsgi.url_scheme"] = "https"  # Secure session cookie needs HTTPS
    return app, client, det, ledger, ext


def upload(client, key=CAM_KEY, body=None):
    return client.post("/api/upload", data=body if body is not None else jpeg(),
                       headers={"X-Camera-Id": "cam-01", "X-API-Key": key, "Content-Type": "image/jpeg"})


def login(client, user, pw):
    page = client.get("/login").get_data(as_text=True)
    token = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    r = client.post("/login", data={"username": user, "password": pw, "csrf": token})
    html = client.get("/").get_data(as_text=True)
    m = re.search(r'name="csrf-token" content="([^"]+)"', html)
    return r, (m.group(1) if m else None)


def drain(ext):
    while not ext["tasks"].empty():
        ext["process"](ext["tasks"].get())


# ---------------------------------------------------------------- unit
def test_encryption_roundtrip_and_tamper(tmp_path):
    store = EvidenceStore(tmp_path, base64.b64encode(os.urandom(32)).decode())
    data = b"jpeg-bytes" * 100
    h = store.save("INC-1", data)
    assert h == sha256_hex(data)
    raw = (tmp_path / "INC-1.enc").read_bytes()
    assert data not in raw                      # really encrypted at rest
    assert store.load("INC-1") == data

    flipped = bytearray(raw); flipped[-1] ^= 1
    (tmp_path / "INC-1.enc").write_bytes(bytes(flipped))
    with pytest.raises(EvidenceTampered):
        store.load("INC-1")

    # A file copied from another incident must not decrypt (AAD binding)
    store.save("INC-2", b"other")
    (tmp_path / "INC-1.enc").write_bytes((tmp_path / "INC-2.enc").read_bytes())
    with pytest.raises(EvidenceTampered):
        store.load("INC-1")


def test_rejects_path_traversal(tmp_path):
    store = EvidenceStore(tmp_path, base64.b64encode(os.urandom(32)).decode())
    with pytest.raises(ValueError):
        store.load("../secret")


def test_zone_uses_feet_position(tmp_path):
    zone = Zone(tmp_path / "z.json")
    zone.set([[0.5, 0.5], [1, 0.5], [1, 1], [0.5, 1]])  # bottom-right quarter
    assert anchor_point([400, 100, 480, 400]) == (440, 400)
    dets = [{"box": [400, 100, 480, 400], "confidence": .9},   # feet inside
            {"box": [400, 10, 480, 200], "confidence": .9},    # feet above zone
            {"box": [10, 300, 100, 470], "confidence": .9}]    # left half
    inside = find_intruders(dets, zone, 640, 480)
    assert len(inside) == 1 and dets[0]["in_zone"] and not dets[1]["in_zone"]
    with pytest.raises(ValueError):
        zone.set([[0, 0], [1, 1]])
    assert Zone(tmp_path / "z.json").points == zone.points   # persisted


# ---------------------------------------------------------------- device API
def test_upload_requires_valid_device_key(env):
    _, client, *_ = env
    assert upload(client, key="wrong").status_code == 401
    assert upload(client, body=b"not a jpeg").status_code == 400
    assert upload(client).status_code == 200


def test_intrusion_creates_incident_records_chain_and_honours_cooldown(env):
    app, client, det, ledger, ext = env
    det.boxes = [(10, 100, 100, 400)]            # left half -> outside default zone
    assert upload(client).get_json()["incident"] is None

    det.boxes = [(400, 100, 480, 400)]           # right half -> inside default zone
    r = upload(client).get_json()
    assert r["intruders"] == 1 and r["incident"]
    inc_id = r["incident"]
    assert upload(client).get_json()["incident"] is None   # cooldown

    drain(ext)
    inc = ext["db"].get_incident(inc_id)
    assert inc["chain_status"] == "recorded"
    assert ledger.records[inc_id]["evidence_hash"] == inc["evidence_hash"]


# ---------------------------------------------------------------- dashboard
def test_login_csrf_and_roles(env):
    app, client, det, ledger, ext = env
    assert client.get("/").status_code == 302                    # redirect to login
    assert client.get("/api/incidents").status_code == 401
    r, _ = login(client, "admin", "wrong")
    assert b"Invalid username" in r.data

    r, token = login(client, "guard", "guard-password")
    assert token
    assert client.get("/api/incidents").status_code == 200
    assert client.post("/api/zone", json={"points": [[0, 0], [1, 0], [1, 1]]},
                       headers={"X-CSRF-Token": token}).status_code == 403   # security role
    assert client.get("/users").status_code == 403

    client2 = app.test_client(); client2.environ_base["wsgi.url_scheme"] = "https"
    _, admin_token = login(client2, "admin", "admin-password")
    pts = [[0, 0], [1, 0], [1, 1]]
    assert client2.post("/api/zone", json={"points": pts}).status_code == 400       # no CSRF
    assert client2.post("/api/zone", json={"points": pts},
                        headers={"X-CSRF-Token": admin_token}).status_code == 200


def test_login_lockout(env):
    _, client, *_ = env
    for _ in range(5):
        login(client, "admin", "nope")
    r, _ = login(client, "admin", "admin-password")
    assert r.status_code == 429


def test_verify_detects_tampering(env):
    app, client, det, ledger, ext = env
    det.boxes = [(400, 100, 480, 400)]
    inc_id = upload(client).get_json()["incident"]
    drain(ext)
    _, token = login(client, "guard", "guard-password")
    verify = lambda: client.post(f"/api/incident/{inc_id}/verify",  # noqa: E731
                                 headers={"X-CSRF-Token": token}).get_json()

    assert verify()["status"] == "VERIFIED"
    ev = client.get(f"/evidence/{inc_id}.jpg?annotated=1")
    assert ev.status_code == 200 and ev.data[:2] == b"\xff\xd8"

    # Attacker rewrites the DB hash -> chain disagrees
    ext["db"].execute("UPDATE incidents SET evidence_hash = ? WHERE id = ?", ("0" * 64, inc_id))
    assert verify()["status"] == "DB_TAMPERED"

    # Attacker replaces the evidence with a validly-encrypted different image
    ext["store"].save(inc_id, jpeg(320, 240))
    assert verify()["status"] == "TAMPERED"

    # Attacker edits encrypted bytes directly
    path = ext["store"].directory / f"{inc_id}.enc"
    b = bytearray(path.read_bytes()); b[40] ^= 0xFF; path.write_bytes(bytes(b))
    r = verify()
    assert r["status"] == "TAMPERED" and not r["verified"]

    assert client.post(f"/api/incident/{inc_id}/ack", headers={"X-CSRF-Token": token}).status_code == 200
    assert ext["db"].get_incident(inc_id)["acknowledged_by"] == "guard"
