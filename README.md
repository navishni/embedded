# Intrusion Detection and Alert System — ESP32-CAM + YOLO11 + AES-256 + Blockchain

```
ESP32-CAM ──Wi-Fi / HTTPS (pinned cert, device API key)──▶ Flask backend
   │                                                         │
   │                          OpenCV decode → YOLO11 person detection
   │                          → restricted-zone check (feet point in polygon)
   │                                                         │ intrusion
   │                     ┌───────────────┬───────────────────┼─────────────────┐
   │              AES-256-GCM      SHA-256 hash        SQLite incident     ntfy alert
   │              evidence file         │                                 (no image sent)
   │                                    ▼
   │                     Web3.py → IncidentLedger.sol (Hardhat local chain)
   ▼
Admin dashboard (HTTPS, login, admin/security roles, CSRF, audit log, verify button)
```

## Folder layout

| Path | What it is |
|---|---|
| `firmware/esp32cam_intrusion/` | Arduino sketch for the AI-Thinker ESP32-CAM |
| `backend/app.py` | Flask server: upload API, dashboard, verification |
| `backend/detector.py` | YOLO11 person detection, restricted zone, annotation |
| `backend/crypto_store.py` | AES-256-GCM evidence storage + SHA-256 |
| `backend/blockchain.py` | Web3.py client for the smart contract |
| `backend/db.py` | SQLite: users, incidents, audit log |
| `backend/notifier.py` | ntfy push alerts |
| `backend/manage.py` | setup: secrets, TLS cert, users, bulk verify |
| `backend/simulate_camera.py` | test without hardware (image file or laptop webcam) |
| `blockchain/contracts/IncidentLedger.sol` | append-only incident ledger |

## 1. One-time setup (laptop)

Prerequisites: Python 3.10+, Node.js 18+, Arduino IDE.

```powershell
# Backend
cd D:\embedded\backend
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\python manage.py init                     # writes .env (secrets, AES key, camera key)
.\.venv\Scripts\python manage.py gen-cert --ip <LAPTOP_LAN_IP>
.\.venv\Scripts\python manage.py create-user admin --role admin

# Blockchain
cd D:\embedded\blockchain
npm install
npm test                                                  # contract unit tests
```

`manage.py init` prints the **camera API key**, and `gen-cert` prints the **certificate PEM**. You need both for the firmware.

> **Back up `EVIDENCE_KEY`** from `backend/.env`. Without it, the stored evidence cannot be decrypted. Running `init --force` creates a new key.

## 2. Run (three terminals)

```powershell
# Terminal 1 – local blockchain (keep running)
cd D:\embedded\blockchain; npx hardhat node

# Terminal 2 – deploy the contract (again after every node restart: the Hardhat node keeps no state)
cd D:\embedded\blockchain; npm run deploy

# Terminal 3 – backend
cd D:\embedded\backend; .\.venv\Scripts\python app.py
```

Open `https://<LAPTOP_LAN_IP>:5000` and accept the self-signed certificate warning once.

Allow inbound TCP 5000 in Windows Firewall so the ESP32 can reach the laptop.

If the chain is down when an intrusion happens, the incident is kept as `pending` and is retried every 60 s (or by an admin via `POST /api/chain/retry`).

## 3. Flash the ESP32-CAM

1. Arduino IDE → Boards Manager → install **esp32 by Espressif**.
2. Copy `firmware/esp32cam_intrusion/secrets.example.h` to `secrets.h`. Fill in the Wi-Fi details, the laptop IP, `CAMERA_ID`, `DEVICE_API_KEY`, and the certificate PEM.
3. Board: **AI Thinker ESP32-CAM**. Partition scheme: *Huge APP*.
4. Wiring with a USB-TTL adapter: 5V→5V, GND→GND, U0R→TX, U0T→RX. Bridge **IO0 to GND** while flashing.
5. Upload, then remove the IO0 jumper and press RESET. Serial Monitor (115200) shows `[HTTP] 200 {...}` for each frame.

## 4. Test without the camera

```powershell
cd D:\embedded\backend
.\.venv\Scripts\python simulate_camera.py --image some_photo.jpg
.\.venv\Scripts\python simulate_camera.py --webcam 0          # laptop webcam, ~5 fps
.\.venv\Scripts\python -m pytest -q tests                      # backend test suite
.\.venv\Scripts\python manage.py verify-all                    # integrity check of all incidents
```

## 5. Using the dashboard

Shortcut: `powershell -ExecutionPolicy Bypass -File D:\embedded\start_all.ps1 [-Webcam]` starts the chain, deploys the contract and starts the server.

- **Dashboard**: alert counters, live camera tiles, a 24-hour activity chart, and the most recent incidents.
- **Live view**: real-time video from each camera after AI processing. Boxes are red inside the zone and green outside, and the banner shows ARMED, DISARMED or INTRUDER.
- **Intrusion alarm** (on every page): when a new incident arrives, a flashing red banner appears with **View** and **Acknowledge** buttons, and a siren plays. Toggle the siren with the 🔊 button; browsers only allow sound after you've clicked the page once. With 🔔 you can turn on desktop pop-up notifications.
- **Incidents**: search and filter by status, camera and date. Export the filtered list as **CSV**, download a **PDF report** for any incident, or acknowledge all open incidents at once.
- **PDF evidence report**: contains the annotated image, incident details, the file, DB and chain SHA-256 hashes, the transaction, the recorder account, the list of detections, and a live integrity check (VERIFIED or TAMPERED).
- **Analytics**: choose 24 h, 7, 30 or 90 days. Shows incidents per day, by hour of day, by weekday, the confidence mix, and per-camera counts, plus the average time to acknowledge and the share recorded on-chain.
- **Arming & schedule** (admin): a master Arm/Disarm switch, which you can also flip from the shield pill in the top bar. Optionally arm only between set hours on chosen weekdays (e.g. 22:00–05:30; overnight ranges work). While disarmed, cameras keep streaming and detecting, but no incidents, alarms or alerts are created.
- **Restricted zone** (admin): click points on the live frame to draw a polygon, then save. A person counts as an intruder when the bottom-centre of their box (their feet) is inside the zone.
- **Incident page**: shows the decrypted evidence with boxes and the zone drawn on it, plus the hashes and the chain transaction. **Verify integrity** re-hashes the stored evidence and compares it with the blockchain record.
- **Users & audit** (admin): manage accounts and roles, and view the audit log of logins, evidence views, report downloads, exports, verifications, and zone and arming changes.

Verification results:

| Status | Meaning |
|---|---|
| `VERIFIED` | file hash == DB hash == on-chain hash |
| `TAMPERED` | encrypted file was edited (GCM tag fails) or replaced (hash ≠ chain) |
| `DB_TAMPERED` | the image is intact but the SQLite record was altered |
| `NOT_ON_CHAIN` / `CHAIN_UNAVAILABLE` | the record isn't on chain yet, or the node is offline |
| `MISSING` | the evidence file was deleted |

## 6. Notifications (ntfy)

`manage.py init` creates a random topic (`NTFY_TOPIC` in `.env`). Install the ntfy app on your phone and subscribe to that topic. Alerts contain only metadata and a link to the dashboard: the image never leaves the server, because ntfy.sh topics are public to anyone who knows the name.

## Security mechanisms

| Mechanism | Implementation |
|---|---|
| Transport encryption | HTTPS/TLS. The ESP32 pins the server certificate (`setCACert`). |
| Device authentication | Per-camera API key, compared in constant time |
| Evidence encryption | AES-256-GCM. A random nonce per file, with the incident ID bound as AAD so files can't be swapped between incidents. |
| Hashing | SHA-256 of the original JPEG, stored in SQLite and on-chain |
| Blockchain | `IncidentLedger.sol`: append-only, duplicate IDs rejected, only authorised recorder accounts can write |
| Dashboard authentication | scrypt password hashes, session-fixation protection, lockout after 5 failed logins, 8 h sessions |
| Access control | `admin` and `security` roles |
| Web hardening | CSRF tokens, strict CSP (no inline JS), HttpOnly/Secure/SameSite cookies, HSTS, no-store on evidence |
| Accountability | Audit log of every login, evidence view, verification, zone and user change |

## Configuration (`backend/.env`)

| Key | Default | Notes |
|---|---|---|
| `CAMERA_KEYS` | — | `cam-01:key,cam-02:key2` to add more cameras |
| `YOLO_MODEL` | `yolo11n.pt` | use `yolo11s.pt` for better accuracy if your laptop is fast enough |
| `CONFIDENCE` | 0.45 | minimum person confidence |
| `ALERT_COOLDOWN_S` | 30 | minimum time between incidents per camera |
| `ETH_PRIVATE_KEY` | empty | empty uses Hardhat's unlocked account #0. Set it for a real network. |
| `NTFY_TOPIC` / `NTFY_TOKEN` | random / empty | |

## Known limitations

- The Flask development server is fine for a prototype. For a deployment, run it behind a production WSGI server.
- The Hardhat node is in-memory: restarting it wipes the chain. For a persistent demo, use a testnet such as Sepolia: set `ETH_RPC_URL` and `ETH_PRIVATE_KEY`, then deploy with `--network`.
- The camera's frame rate is limited by YOLO inference time on the laptop CPU (about 50–150 ms per frame with `yolo11n`).
