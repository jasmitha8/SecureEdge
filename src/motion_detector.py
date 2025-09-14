import cv2
import numpy as np
import time
# import winsound  # for sound alerts (Windows only, remove if not needed)
from ultralytics import YOLO

# -----------------------------
# Load YOLO model
# -----------------------------
yolo_model = YOLO("yolov8n.pt")  # try yolov8m.pt or yolov8l.pt for higher accuracy

# -----------------------------
# Video capture
# -----------------------------
cap = cv2.VideoCapture(0)

# Alert system
alert_cooldown = 5  # seconds
last_alerts = {"phone": 0, "peek": 0, "approach": 0}

EDGE_THRESHOLD = 0.1       # for peeking detection
APPROACH_THRESHOLD = 1.25  # area increase factor for approaching

prev_people = {}

# Sound helper
def beep_alert():
    try:
        winsound.Beep(1000, 300)  # freq=1000Hz, duration=300ms
    except:
        pass  # skip if not on Windows

while True:
    ret, frame = cap.read()
    if not ret:
        break
    h, w = frame.shape[:2]

    # Detection flags
    detections = {"phone": False, "peek": False, "approach": False}
    people_this_frame = {}

    # -----------------------------
    # YOLO detection
    # -----------------------------
    results = yolo_model.predict(frame, verbose=False)
    for r in results:
        if r.boxes is None or len(r.boxes) == 0:
            continue
        for box in r.boxes:
            cls_id = int(box.cls)
            cls_name = r.names[cls_id].lower()
            x1, y1, x2, y2 = map(int, box.xyxy[0].cpu().numpy())
            cx, cy = (x1 + x2) // 2, (y1 + y2) // 2
            area = (x2 - x1) * (y2 - y1)

            # ----- Phone detection -----
            if cls_name in ["cell phone", "phone", "mobile phone"]:
                detections["phone"] = True
                cv2.rectangle(frame, (x1, y1), (x2, y2), (0, 0, 255), 2)
                cv2.putText(frame, "Phone", (x1, y1 - 10),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)

            # ----- Peeking detection -----
            if cls_name == "person":
                if cx < w * EDGE_THRESHOLD or cx > w * (1 - EDGE_THRESHOLD):
                    detections["peek"] = True
                    cv2.putText(frame, "Peeking", (x1, y1 - 10),
                                cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2)
                cv2.rectangle(frame, (x1, y1), (x2, y2), (0, 255, 0), 2)

                # Track for approach detection
                people_this_frame[(cx, cy)] = area

    # -----------------------------
    # Approach detection (compare with previous frame)
    # -----------------------------
    for center, area in people_this_frame.items():
        closest_prev = None
        min_dist = float("inf")
        for p_center, p_area in prev_people.items():
            dist = np.linalg.norm(np.array(center) - np.array(p_center))
            if dist < min_dist:
                min_dist = dist
                closest_prev = p_center
        if closest_prev is not None:
            prev_area = prev_people[closest_prev]
            if area / (prev_area + 1e-5) > APPROACH_THRESHOLD:
                detections["approach"] = True
    prev_people = people_this_frame

    # -----------------------------
    # Dashboard overlay
    # -----------------------------
    now = time.time()
    y_offset = 40
    for alert_type, detected in detections.items():
        color = (0, 200, 0)  # green = safe
        label = f"{alert_type.upper()}: SAFE"

        if detected:
            if now - last_alerts[alert_type] > alert_cooldown:
                last_alerts[alert_type] = now
                beep_alert()
            color = (0, 0, 255) if alert_type == "phone" else (0, 255, 255)
            label = f"ALERT: {alert_type.upper()} DETECTED!"

        cv2.putText(frame, label, (20, y_offset),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.9, color, 3)
        y_offset += 40

    # Show feed
    cv2.imshow("Screen Security Dashboard", frame)
    if cv2.waitKey(1) & 0xFF == ord("q"):
        break

cap.release()
cv2.destroyAllWindows()

