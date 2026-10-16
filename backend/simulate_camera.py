"""Stand-in for the ESP32-CAM: uploads images (or webcam frames) over HTTPS.

  python simulate_camera.py --image photo.jpg            send one image
  python simulate_camera.py --webcam 0 --interval 1      stream from a laptop webcam

Uses the same headers as the firmware and pins certs/server.crt, so it also
exercises device authentication and TLS.
"""
import argparse
import os
import time
from pathlib import Path

import requests
from dotenv import dotenv_values

BASE = Path(__file__).resolve().parent


def main():
    env = {**dotenv_values(BASE / ".env"), **os.environ}
    keys = dict(i.split(":", 1) for i in env.get("CAMERA_KEYS", "").split(",") if ":" in i)
    p = argparse.ArgumentParser()
    p.add_argument("--url", default=f"https://127.0.0.1:{env.get('PORT', '5000')}/api/upload")
    p.add_argument("--camera", default=next(iter(keys), "cam-01"))
    p.add_argument("--image", type=Path)
    p.add_argument("--webcam", type=int)
    p.add_argument("--interval", type=float, default=0.2, help="seconds between webcam frames")
    p.add_argument("--cert", default=str(BASE / "certs" / "server.crt"))
    a = p.parse_args()

    headers = {"X-Camera-Id": a.camera, "X-API-Key": keys.get(a.camera, ""),
               "Content-Type": "image/jpeg"}

    def send(jpeg):
        try:
            r = requests.post(a.url, data=jpeg, headers=headers, verify=a.cert, timeout=30)
            print(r.status_code, r.text.strip())
        except requests.ConnectionError:
            print(f"Server not reachable at {a.url} - is `python app.py` running? retrying...")
            time.sleep(3)

    if a.image:
        send(a.image.read_bytes())
    elif a.webcam is not None:
        import cv2
        cap = cv2.VideoCapture(a.webcam)
        try:
            while True:
                ok, frame = cap.read()
                if ok:
                    send(cv2.imencode(".jpg", cv2.resize(frame, (640, 480)))[1].tobytes())
                time.sleep(a.interval)
        except KeyboardInterrupt:
            pass
        finally:
            cap.release()
    else:
        p.error("give --image or --webcam")


if __name__ == "__main__":
    main()
