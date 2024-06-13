from ultralytics import YOLO
from ultralytics.solutions import object_counter
import cv2

from pymongo import MongoClient
import datetime
from shapely.geometry import Point


# Setup MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['object_counter_db']
collection = db['detections']

model = YOLO("model/best80.pt")
region_of_interest = [(300, 20), (302, 680), (280, 680), (280, 20)]
counter = object_counter.ObjectCounter()
counter.set_args(view_img=True, reg_pts=region_of_interest, classes_names=model.names, draw_tracks=True)

def count_object():
    cap = cv2.VideoCapture(0)
    assert cap.isOpened()
    tracked_ids = set()
    while True:
        success, im0 = cap.read()
        if not success:
            break
        tracks = model.track(im0, persist=True, show=False)
        im0 = counter.start_counting(im0, tracks)
        
        # Process tracks and save to MongoDB if crossing the ROI
        if tracks[0].boxes.id is not None:
            boxes = tracks[0].boxes.xyxy.cpu()
            clss = tracks[0].boxes.cls.cpu().tolist()
            track_ids = tracks[0].boxes.id.int().cpu().tolist()

            for box, track_id, cls in zip(boxes, track_ids, clss):
                if track_id not in tracked_ids:
                    prev_position = counter.track_history[track_id][-2] if len(counter.track_history[track_id]) > 1 else None
                    current_position = (float((box[0] + box[2]) / 2), float((box[1] + box[3]) / 2))
                    
                    if len(region_of_interest) >= 3:
                        is_inside = counter.counting_region.contains(Point(current_position))
                        if prev_position and is_inside:
                            tracked_ids.add(track_id)
                            direction = "IN" if (box[0] - prev_position[0]) * (counter.counting_region.centroid.x - prev_position[0]) > 0 else "OUT"
                            detection = {
                                "class": counter.names[cls],
                                "direction": direction,
                                "timestamp": datetime.datetime.now()
                            }
                            collection.insert_one(detection)

        ret, buffer = cv2.imencode('.jpg', im0)
        frame = buffer.tobytes()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

    cap.release()

    # Realtime Object Detection & Counting
@app.route('/realtime')
def index():
    return render_template('index.html')

@app.route('/video_feed')
def video_feed():
    return Response(count_object(), mimetype='multipart/x-mixed-replace; boundary=frame')