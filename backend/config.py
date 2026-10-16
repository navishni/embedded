"""Central configuration, loaded from environment variables / backend/.env."""
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _path(name, default):
    p = Path(os.getenv(name, default))
    return p if p.is_absolute() else BASE_DIR / p


class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "")

    # Storage
    DATA_DIR = _path("DATA_DIR", "data")
    DB_PATH = DATA_DIR / "intrusion.db"
    EVIDENCE_DIR = DATA_DIR / "evidence"
    ZONE_FILE = DATA_DIR / "zone.json"

    # AES-256 key: base64 of 32 random bytes. Kept out of the evidence folder.
    EVIDENCE_KEY = os.getenv("EVIDENCE_KEY", "")

    # TLS
    TLS_CERT = _path("TLS_CERT", "certs/server.crt")
    TLS_KEY = _path("TLS_KEY", "certs/server.key")
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", "5000"))

    # Camera device keys: "cam-01:key1,cam-02:key2"
    CAMERA_KEYS = dict(
        item.split(":", 1)
        for item in os.getenv("CAMERA_KEYS", "").split(",")
        if ":" in item
    )

    # Detection
    YOLO_MODEL = os.getenv("YOLO_MODEL", "yolo11n.pt")
    CONFIDENCE = float(os.getenv("CONFIDENCE", "0.45"))
    ALERT_COOLDOWN_S = int(os.getenv("ALERT_COOLDOWN_S", "30"))
    MAX_UPLOAD_BYTES = 2 * 1024 * 1024

    # Notifications (ntfy)
    NTFY_SERVER = os.getenv("NTFY_SERVER", "https://ntfy.sh")
    NTFY_TOPIC = os.getenv("NTFY_TOPIC", "")
    NTFY_TOKEN = os.getenv("NTFY_TOKEN", "")
    DASHBOARD_URL = os.getenv("DASHBOARD_URL", "")

    # Blockchain
    ETH_RPC_URL = os.getenv("ETH_RPC_URL", "http://127.0.0.1:8545")
    ETH_PRIVATE_KEY = os.getenv("ETH_PRIVATE_KEY", "")  # empty -> use node's unlocked account[0]
    CONTRACT_INFO = _path("CONTRACT_INFO", "../blockchain/deployments/IncidentLedger.json")

    # Login throttling
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_S = 300
