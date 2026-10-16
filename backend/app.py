"""Flask backend: receives ESP32-CAM frames, detects intrusions, secures evidence.

Pipeline per frame:
  device auth -> decode (OpenCV) -> YOLO11 person detection -> restricted-zone
  check -> [intrusion] AES-256-GCM evidence + SHA-256 hash -> SQLite incident
  -> ntfy alert + blockchain record (background worker)
"""
import hmac
import logging
import queue
import secrets
import threading
import time
from datetime import datetime, timedelta
from functools import wraps

import cv2
from flask import (Flask, Response, abort, flash, g, jsonify, redirect,
                   render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from blockchain import BlockchainUnavailable, Ledger
from config import Config
from crypto_store import EvidenceStore, EvidenceTampered, sha256_hex
from db import Database
from detector import PersonDetector, Zone, annotate, decode_jpeg, find_intruders
from notifier import Notifier
from reports import incident_pdf, incidents_csv
from settings import SystemSettings

log = logging.getLogger("intrusion")

ROLES = ("admin", "security")


def create_app(cfg=Config, detector=None, ledger=None, notifier=None, start_worker=True):
    if not cfg.SECRET_KEY:
        raise RuntimeError("FLASK_SECRET_KEY is not set - run `python manage.py init`")

    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=cfg.SECRET_KEY,
        MAX_CONTENT_LENGTH=cfg.MAX_UPLOAD_BYTES,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_SAMESITE="Strict",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    )

    db = Database(cfg.DB_PATH)
    store = EvidenceStore(cfg.EVIDENCE_DIR, cfg.EVIDENCE_KEY)
    zone = Zone(cfg.ZONE_FILE)
    settings = SystemSettings(cfg.DATA_DIR / "settings.json")
    detector = detector or PersonDetector(cfg.YOLO_MODEL, cfg.CONFIDENCE)
    ledger = ledger or Ledger(cfg.ETH_RPC_URL, cfg.CONTRACT_INFO, cfg.ETH_PRIVATE_KEY)
    notifier = notifier or Notifier(cfg.NTFY_SERVER, cfg.NTFY_TOPIC, cfg.NTFY_TOKEN, cfg.DASHBOARD_URL)

    latest = {}                 # camera_id -> {"jpeg": bytes, "at": ts, "people": n, "intruders": n}
    last_alert = {}             # camera_id -> ts of last incident (cooldown)
    login_failures = {}         # key -> [count, first_ts]
    state_lock = threading.Lock()
    frame_ready = threading.Condition()   # wakes live-stream viewers on each new frame
    tasks = queue.Queue()

    app.extensions["intrusion"] = dict(db=db, store=store, zone=zone, ledger=ledger,
                                       notifier=notifier, tasks=tasks, latest=latest,
                                       settings=settings)

    # ------------------------------------------------------------ background
    def record_on_chain(inc):
        try:
            tx = ledger.record(inc["id"], inc["timestamp"], inc["camera_id"], inc["evidence_hash"])
            db.set_chain(inc["id"], "recorded", tx)
            log.info("incident %s recorded on chain (tx %s)", inc["id"], tx)
        except BlockchainUnavailable as e:
            db.set_chain(inc["id"], "pending")
            log.warning("blockchain record deferred for %s: %s", inc["id"], e)

    def process(inc):
        if notifier.send_intrusion(inc):
            db.set_notified(inc["id"])
        record_on_chain(inc)

    def worker():
        next_retry = time.time() + 60
        while True:
            try:
                inc = tasks.get(timeout=5)
                process(inc)
            except queue.Empty:
                pass
            except Exception:
                log.exception("background task failed")
            if time.time() >= next_retry:
                next_retry = time.time() + 60
                for inc in db.pending_chain():
                    record_on_chain(inc)

    if start_worker:
        threading.Thread(target=worker, daemon=True, name="incident-worker").start()
    app.extensions["intrusion"]["process"] = process

    # ------------------------------------------------------------ security helpers
    @app.before_request
    def load_user():
        g.user = None
        if "username" in session:
            user = db.get_user(session["username"])
            if user:
                g.user = {"username": user["username"], "role": user["role"]}
            else:
                session.clear()
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)

    def check_csrf():
        token = request.headers.get("X-CSRF-Token") or request.form.get("csrf")
        if not token or not hmac.compare_digest(token, session.get("csrf", "")):
            abort(400, "CSRF token missing or invalid")

    def login_required(role=None):
        def deco(fn):
            @wraps(fn)
            def wrapper(*a, **kw):
                if not g.user:
                    if request.path.startswith("/api/"):
                        abort(401)
                    return redirect(url_for("login", next=request.path))
                if role and g.user["role"] != role:
                    abort(403)
                if request.method == "POST":
                    check_csrf()
                return fn(*a, **kw)
            return wrapper
        return deco

    @app.context_processor
    def inject():
        return {"current_user": g.get("user"), "csrf_token": session.get("csrf", ""),
                "arm_status": settings.status() if g.get("user") else None,
                "nav": request.endpoint}

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' blob: data:; style-src 'self'; "
            "script-src 'self'; frame-ancestors 'none'")
        return resp

    # ------------------------------------------------------------ device API
    @app.post("/api/upload")
    def upload():
        camera_id = request.headers.get("X-Camera-Id", "")
        api_key = request.headers.get("X-API-Key", "")
        expected = cfg.CAMERA_KEYS.get(camera_id)
        if not expected or not hmac.compare_digest(api_key, expected):
            log.warning("rejected upload from %s (camera %r)", request.remote_addr, camera_id)
            abort(401)

        data = request.get_data()
        image = decode_jpeg(data) if data else None
        if image is None:
            abort(400, "body must be a JPEG image")
        h, w = image.shape[:2]

        detections = detector.detect(image)
        intruders = find_intruders(detections, zone, w, h)
        now = int(time.time())

        armed = settings.status()["armed"]

        live = annotate(image, detections, zone.points)
        if not armed:
            banner, color = f"DISARMED - {len(detections)} person(s), no alerts", (120, 90, 20)
        elif intruders:
            banner, color = f"INTRUDER IN ZONE ({len(intruders)})", (0, 0, 200)
        else:
            banner, color = f"ARMED - {len(detections)} person(s), zone clear", (40, 40, 40)
        cv2.rectangle(live, (0, 0), (w, 30), color, -1)
        cv2.putText(live, f"{camera_id}  {time.strftime('%H:%M:%S')}  {banner}", (8, 21),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.55, (255, 255, 255), 1, cv2.LINE_AA)
        ok, annotated_jpeg = cv2.imencode(".jpg", live)
        with state_lock:
            latest[camera_id] = {"jpeg": annotated_jpeg.tobytes() if ok else b"", "at": now,
                                 "people": len(detections), "intruders": len(intruders),
                                 "armed": armed}
            in_cooldown = now - last_alert.get(camera_id, 0) < cfg.ALERT_COOLDOWN_S
            raise_incident = armed and bool(intruders) and not in_cooldown
            if raise_incident:
                last_alert[camera_id] = now
        with frame_ready:
            frame_ready.notify_all()

        result = {"people": len(detections), "intruders": len(intruders), "armed": armed, "incident": None}
        if raise_incident:
            incident_id = f"INC-{time.strftime('%Y%m%d-%H%M%S', time.gmtime(now))}-{secrets.token_hex(3)}"
            evidence_hash = store.save(incident_id, data)
            inc = {
                "id": incident_id, "camera_id": camera_id, "timestamp": now,
                "person_count": len(intruders),
                "max_confidence": max(d["confidence"] for d in intruders),
                "detections": detections, "zone": zone.points, "evidence_hash": evidence_hash,
            }
            db.add_incident(inc)
            db.audit(f"device:{camera_id}", "incident_created", incident_id)
            log.warning("INTRUSION %s on %s: %d person(s)", incident_id, camera_id, len(intruders))
            tasks.put(inc)
            result["incident"] = incident_id
        return jsonify(result)

    # ------------------------------------------------------------ auth pages
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            check_csrf()
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            key = f"{request.remote_addr}|{username.lower()}"
            now = time.time()
            with state_lock:
                count, first = login_failures.get(key, [0, now])
                if now - first > cfg.LOCKOUT_S:
                    count, first = 0, now
                locked = count >= cfg.MAX_LOGIN_ATTEMPTS
            if locked:
                flash("Too many failed attempts. Try again in a few minutes.", "error")
                return render_template("login.html"), 429

            user = db.get_user(username)
            if user and check_password_hash(user["password_hash"], password):
                with state_lock:
                    login_failures.pop(key, None)
                session.clear()                     # prevent session fixation
                session.permanent = True
                session["username"] = user["username"]
                session["csrf"] = secrets.token_urlsafe(32)
                db.audit(username, "login")
                nxt = request.args.get("next", "")
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("dashboard"))

            with state_lock:
                login_failures[key] = [count + 1, first]
            db.audit(username or "?", "login_failed", request.remote_addr)
            flash("Invalid username or password.", "error")
        return render_template("login.html")

    @app.post("/logout")
    @login_required()
    def logout():
        db.audit(g.user["username"], "logout")
        session.clear()
        return redirect(url_for("login"))

    # ------------------------------------------------------------ dashboard
    @app.get("/")
    @login_required()
    def dashboard():
        return render_template("dashboard.html", cameras=sorted(cfg.CAMERA_KEYS))

    @app.get("/incident/<incident_id>")
    @login_required()
    def incident_page(incident_id):
        inc = db.get_incident(incident_id)
        if not inc:
            abort(404)
        return render_template("incident.html", inc=inc)

    @app.get("/zone")
    @login_required("admin")
    def zone_page():
        return render_template("zone.html", cameras=sorted(cfg.CAMERA_KEYS))

    @app.get("/users")
    @login_required("admin")
    def users_page():
        return render_template("users.html", users=db.list_users(), audit=db.recent_audit(), roles=ROLES)

    # ------------------------------------------------------------ dashboard API
    @app.get("/api/incidents")
    @login_required()
    def api_incidents():
        limit = min(int(request.args.get("limit", 100)), 500)
        rows = db.list_incidents(limit)
        for r in rows:
            r.pop("detections"); r.pop("zone")
        cams = {cid: {k: v for k, v in info.items() if k != "jpeg"} for cid, info in latest.items()}
        return jsonify({"incidents": rows, "stats": db.stats(), "cameras": cams,
                        "notifications": notifier.enabled})

    @app.get("/api/live/<camera_id>.jpg")
    @login_required()
    def api_live(camera_id):
        info = latest.get(camera_id)
        if not info or not info["jpeg"]:
            abort(404)
        return Response(info["jpeg"], mimetype="image/jpeg", headers={"Cache-Control": "no-store"})

    @app.get("/api/stream/<camera_id>")
    @login_required()
    def api_stream(camera_id):
        """MJPEG live video: pushes each processed frame to the browser as it arrives."""
        def frames():
            # Close each part with the next boundary straight away: browsers only
            # paint an MJPEG frame once they see the following boundary.
            yield b"--frame\r\n"
            last_sent = None
            first = True
            while True:
                if not first:                       # send the current frame immediately on connect
                    with frame_ready:
                        frame_ready.wait(timeout=5)
                first = False
                info = latest.get(camera_id)
                if not info or not info["jpeg"] or info["jpeg"] is last_sent:
                    continue
                last_sent = info["jpeg"]
                yield (b"Content-Type: image/jpeg\r\nContent-Length: " + str(len(last_sent)).encode()
                       + b"\r\n\r\n" + last_sent + b"\r\n--frame\r\n")
        return Response(frames(), mimetype="multipart/x-mixed-replace; boundary=frame",
                        headers={"Cache-Control": "no-store"})

    @app.get("/live")
    @login_required()
    def live_page():
        return render_template("live.html", cameras=sorted(cfg.CAMERA_KEYS))

    @app.get("/incidents")
    @login_required()
    def incidents_page():
        return render_template("incidents.html", cameras=sorted(cfg.CAMERA_KEYS))

    @app.get("/analytics")
    @login_required()
    def analytics_page():
        return render_template("analytics.html")

    @app.get("/settings")
    @login_required("admin")
    def settings_page():
        return render_template("settings.html", cfg=cfg, chain_info=cfg.CONTRACT_INFO.exists(),
                               notifications=notifier.enabled)

    def _search_args():
        a = request.args
        def ts(name, plus_day=False):
            v = a.get(name, "")
            if not v:
                return None
            try:
                return int(datetime.strptime(v, "%Y-%m-%d").timestamp()) + (86400 if plus_day else 0)
            except ValueError:
                abort(400, f"{name} must be YYYY-MM-DD")
        return dict(status=a.get("status", ""), camera=a.get("camera", ""), q=a.get("q", "").strip(),
                    since=ts("from"), until=ts("to", plus_day=True))

    @app.get("/api/incidents/search")
    @login_required()
    def api_incident_search():
        rows = db.search_incidents(**_search_args(), limit=min(int(request.args.get("limit", 500)), 2000))
        for r in rows:
            r.pop("detections"); r.pop("zone")
        return jsonify({"incidents": rows})

    @app.get("/export/incidents.csv")
    @login_required()
    def export_csv():
        rows = db.search_incidents(**_search_args(), limit=100000)
        db.audit(g.user["username"], "incidents_exported", f"{len(rows)} rows")
        name = f"incidents-{datetime.now():%Y%m%d-%H%M}.csv"
        return Response(incidents_csv(rows), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={name}",
                                 "Cache-Control": "no-store"})

    @app.get("/incident/<incident_id>/report.pdf")
    @login_required()
    def incident_report(incident_id):
        inc = db.get_incident(incident_id)
        if not inc:
            abort(404)
        verification = verify_incident(inc)
        try:
            img = decode_jpeg(store.load(incident_id))
            annotated = cv2.imencode(".jpg", annotate(img, inc["detections"], inc["zone"]))[1].tobytes()
        except (FileNotFoundError, EvidenceTampered):
            annotated = None
        pdf = incident_pdf(inc, annotated, verification, g.user["username"])
        db.audit(g.user["username"], "report_generated", f"{incident_id}: {verification['status']}")
        return Response(pdf, mimetype="application/pdf",
                        headers={"Content-Disposition": f"attachment; filename={incident_id}.pdf",
                                 "Cache-Control": "no-store, private"})

    @app.get("/api/alerts")
    @login_required()
    def api_alerts():
        """Lightweight poll used by every page for the alarm banner."""
        now = time.time()
        cams = {cid: {"online": now - info["at"] < 15, "intruders": info["intruders"],
                      "people": info["people"]} for cid, info in latest.items()}
        return jsonify({"latest": db.latest_incident(), "open": db.stats()["open"] or 0,
                        "arm": {k: v for k, v in settings.status().items() if k != "settings"},
                        "cameras": cams})

    @app.post("/api/incidents/ack-all")
    @login_required()
    def api_ack_all():
        n = db.acknowledge_all(g.user["username"])
        db.audit(g.user["username"], "incidents_acknowledged_all", f"{n} incidents")
        return jsonify({"acknowledged": n})

    @app.get("/api/analytics")
    @login_required()
    def api_analytics():
        days = max(1, min(int(request.args.get("days", 7)), 365))
        return jsonify(db.analytics(days))

    @app.get("/api/settings")
    @login_required()
    def api_settings_get():
        return jsonify(settings.status())

    @app.post("/api/settings")
    @login_required("admin")
    def api_settings_set():
        try:
            status = settings.update(request.get_json(silent=True) or {})
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        db.audit(g.user["username"], "settings_updated",
                 f"armed={status['settings']['armed']} schedule={status['settings']['schedule']}")
        return jsonify(status)

    @app.get("/evidence/<incident_id>.jpg")
    @login_required()
    def evidence(incident_id):
        inc = db.get_incident(incident_id)
        if not inc:
            abort(404)
        try:
            data = store.load(incident_id)
        except FileNotFoundError:
            abort(404)
        except EvidenceTampered:
            abort(409, "evidence failed integrity check")
        if request.args.get("annotated") == "1":
            img = decode_jpeg(data)
            ok, buf = cv2.imencode(".jpg", annotate(img, inc["detections"], inc["zone"]))
            data = buf.tobytes()
        db.audit(g.user["username"], "evidence_viewed", incident_id)
        return Response(data, mimetype="image/jpeg",
                        headers={"Cache-Control": "no-store, private"})

    @app.post("/api/incident/<incident_id>/ack")
    @login_required()
    def api_ack(incident_id):
        if not db.get_incident(incident_id):
            abort(404)
        db.acknowledge(incident_id, g.user["username"])
        db.audit(g.user["username"], "incident_acknowledged", incident_id)
        return jsonify({"ok": True})

    @app.post("/api/incident/<incident_id>/verify")
    @login_required()
    def api_verify(incident_id):
        inc = db.get_incident(incident_id)
        if not inc:
            abort(404)
        report = verify_incident(inc)
        db.audit(g.user["username"], "evidence_verified", f"{incident_id}: {report['status']}")
        return jsonify(report)

    def verify_incident(inc):
        """Recompute the evidence hash and compare with the blockchain record."""
        report = {"incident": inc["id"], "db_hash": inc["evidence_hash"],
                  "file_hash": None, "chain_hash": None, "chain": None}
        try:
            report["file_hash"] = sha256_hex(store.load(inc["id"]))
        except FileNotFoundError:
            report.update(status="MISSING", verified=False, message="Evidence file is missing.")
            return report
        except EvidenceTampered:
            report.update(status="TAMPERED", verified=False,
                          message="Encrypted evidence file was modified (AES-GCM authentication failed).")
            return report

        try:
            onchain = ledger.fetch(inc["id"])
        except BlockchainUnavailable as e:
            local_ok = report["file_hash"] == inc["evidence_hash"]
            report.update(status="CHAIN_UNAVAILABLE", verified=False,
                          message=f"Blockchain unreachable ({e}). Local hash "
                                  f"{'matches' if local_ok else 'DOES NOT match'} the database.")
            return report
        if onchain is None:
            report.update(status="NOT_ON_CHAIN", verified=False,
                          message="No blockchain record for this incident yet.")
            return report

        report["chain_hash"] = onchain["evidence_hash"]
        report["chain"] = onchain
        if report["file_hash"] != onchain["evidence_hash"]:
            report.update(status="TAMPERED", verified=False,
                          message="Evidence hash does not match the blockchain record.")
        elif inc["evidence_hash"] != onchain["evidence_hash"] or \
                onchain["camera_id"] != inc["camera_id"] or onchain["timestamp"] != inc["timestamp"]:
            report.update(status="DB_TAMPERED", verified=False,
                          message="Evidence is intact, but the database record differs from the blockchain.")
        else:
            report.update(status="VERIFIED", verified=True,
                          message="Evidence matches the tamper-evident blockchain record.")
        return report

    app.extensions["intrusion"]["verify"] = verify_incident

    @app.get("/api/zone")
    @login_required()
    def api_zone_get():
        return jsonify({"points": zone.points})

    @app.post("/api/zone")
    @login_required("admin")
    def api_zone_set():
        points = (request.get_json(silent=True) or {}).get("points")
        try:
            zone.set(points)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        db.audit(g.user["username"], "zone_updated", str(zone.points))
        return jsonify({"points": zone.points})

    @app.post("/api/chain/retry")
    @login_required("admin")
    def api_chain_retry():
        pending = db.pending_chain()
        for inc in pending:
            record_on_chain(inc)
        return jsonify({"retried": len(pending), "remaining": len(db.pending_chain())})

    @app.post("/users")
    @login_required("admin")
    def users_create():
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "security")
        if not username or role not in ROLES:
            flash("Username and a valid role are required.", "error")
        elif len(password) < 10:
            flash("Password must be at least 10 characters.", "error")
        elif db.get_user(username):
            flash("That username already exists.", "error")
        else:
            db.add_user(username, generate_password_hash(password), role)
            db.audit(g.user["username"], "user_created", f"{username} ({role})")
            flash(f"User {username} created.", "ok")
        return redirect(url_for("users_page"))

    @app.post("/users/<username>/delete")
    @login_required("admin")
    def users_delete(username):
        user = db.get_user(username)
        if not user:
            abort(404)
        if username == g.user["username"]:
            flash("You cannot delete your own account.", "error")
        elif user["role"] == "admin" and db.count_admins() <= 1:
            flash("Cannot delete the last admin.", "error")
        else:
            db.delete_user(username)
            db.audit(g.user["username"], "user_deleted", username)
            flash(f"User {username} deleted.", "ok")
        return redirect(url_for("users_page"))

    @app.errorhandler(401)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(409)
    def json_errors(e):
        if request.path.startswith("/api/") or request.path.startswith("/evidence/"):
            return jsonify({"error": e.description}), e.code
        return render_template("error.html", error=e), e.code

    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if not (Config.TLS_CERT.exists() and Config.TLS_KEY.exists()):
        raise SystemExit("TLS certificate missing - run `python manage.py gen-cert --ip <your LAN IP>`")
    application = create_app()
    log.info("serving HTTPS on %s:%s", Config.HOST, Config.PORT)
    application.run(host=Config.HOST, port=Config.PORT, threaded=True,
                    ssl_context=(str(Config.TLS_CERT), str(Config.TLS_KEY)))
