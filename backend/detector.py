"""YOLO11 person detection and restricted-zone verification."""
import json
import threading

import cv2
import numpy as np

PERSON_CLASS = 0  # COCO class id for "person"

# Default zone: right half of the frame. Points are normalised (0..1) x,y.
DEFAULT_ZONE = [[0.5, 0.0], [1.0, 0.0], [1.0, 1.0], [0.5, 1.0]]


def decode_jpeg(data: bytes):
    """Decode JPEG bytes to a BGR image, or None if invalid."""
    arr = np.frombuffer(data, dtype=np.uint8)
    return cv2.imdecode(arr, cv2.IMREAD_COLOR)


class Zone:
    """Polygon restricted zone stored in normalised coordinates."""

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self.points = self._load()

    def _load(self):
        try:
            pts = json.loads(self.path.read_text())["points"]
            if self.valid(pts):
                return pts
        except (OSError, ValueError, KeyError, TypeError):
            pass
        return DEFAULT_ZONE

    @staticmethod
    def valid(points):
        return (
            isinstance(points, list)
            and len(points) >= 3
            and all(
                isinstance(p, (list, tuple)) and len(p) == 2
                and all(isinstance(v, (int, float)) and 0 <= v <= 1 for v in p)
                for p in points
            )
        )

    def set(self, points):
        if not self.valid(points):
            raise ValueError("zone needs >= 3 points with coordinates in [0, 1]")
        with self._lock:
            self.points = [[float(x), float(y)] for x, y in points]
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps({"points": self.points}))

    def contains(self, x, y, width, height):
        poly = pixel_polygon(self.points, width, height)
        return cv2.pointPolygonTest(poly, (float(x), float(y)), False) >= 0


def pixel_polygon(points, width, height):
    return np.array([[x * width, y * height] for x, y in points], dtype=np.float32)


def anchor_point(box):
    """Bottom-centre of a bounding box - where the person's feet touch the floor.

    Using the feet rather than the box centre means a person standing just
    outside the zone (whose upper body overlaps it in the image) is not flagged.
    """
    x1, y1, x2, y2 = box
    return (x1 + x2) / 2.0, y2


def find_intruders(detections, zone, width, height):
    """Mark each detection with in_zone and return only those inside the zone."""
    intruders = []
    for d in detections:
        ax, ay = anchor_point(d["box"])
        d["in_zone"] = zone.contains(ax, ay, width, height)
        if d["in_zone"]:
            intruders.append(d)
    return intruders


class PersonDetector:
    """Thin wrapper around an Ultralytics YOLO11 model, loaded lazily."""

    def __init__(self, model_name, confidence):
        self.model_name = model_name
        self.confidence = confidence
        self._model = None
        self._lock = threading.Lock()

    def _ensure_model(self):
        if self._model is None:
            from ultralytics import YOLO  # heavy import, defer until first use
            self._model = YOLO(self.model_name)

    def detect(self, image):
        """Return a list of {"box": [x1,y1,x2,y2], "confidence": float} for people."""
        with self._lock:
            self._ensure_model()
            results = self._model.predict(
                image, classes=[PERSON_CLASS], conf=self.confidence, verbose=False
            )
        out = []
        for r in results:
            for box, conf in zip(r.boxes.xyxy.tolist(), r.boxes.conf.tolist()):
                out.append({"box": [round(v, 1) for v in box], "confidence": round(conf, 3)})
        return out


def annotate(image, detections, zone_points):
    """Draw the zone and bounding boxes (red = inside zone, green = outside)."""
    img = image.copy()
    h, w = img.shape[:2]
    poly = pixel_polygon(zone_points, w, h).astype(np.int32)
    overlay = img.copy()
    cv2.fillPoly(overlay, [poly], (0, 0, 255))
    img = cv2.addWeighted(overlay, 0.15, img, 0.85, 0)
    cv2.polylines(img, [poly], True, (0, 0, 255), 2)

    for d in detections:
        x1, y1, x2, y2 = map(int, d["box"])
        color = (0, 0, 255) if d.get("in_zone") else (0, 200, 0)
        cv2.rectangle(img, (x1, y1), (x2, y2), color, 2)
        label = f"person {d['confidence']:.2f}"
        cv2.putText(img, label, (x1, max(y1 - 6, 12)), cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 2)
        ax, ay = anchor_point(d["box"])
        cv2.circle(img, (int(ax), int(ay)), 4, color, -1)
    return img
