# from flask import Flask, Response, render_template
# from ultralytics import YOLO
# import cv2
# from pymongo import MongoClient
# import datetime as dt

# # Initialize Flask app
# app = Flask(__name__)

# # Setup MongoDB
# client = MongoClient('mongodb://localhost:27017/')
# db = client['coba']
# collection = db['bayu']

# @app.route('/')
# def index():
#     return render_template('video.html')

# def detect_objects():
#     # Load the YOLOv8 model with .pt weights
#     model = YOLO('model/best.pt')

#     # Open camera
#     cap = cv2.VideoCapture(0)

#     try:
#         while True:
#             # Read frame from the camera
#             ret, frame = cap.read()

#             if not ret:
#                 break

#             frame = cv2.flip(frame, 1)

#             # Perform inference on the image
#             results = model(frame)

#             # Get detection results
#             pred_boxes = results[0].boxes.xyxy.cpu().numpy()
#             pred_scores = results[0].boxes.conf.cpu().numpy()
#             pred_classes = results[0].boxes.cls.cpu().numpy()

#             # Draw bounding boxes and labels on the frame
#             for i, box in enumerate(pred_boxes):
#                 x1, y1, x2, y2 = map(int, box)
#                 label = f'{model.names[int(pred_classes[i])]} {pred_scores[i]:.2f}'
#                 cv2.rectangle(frame, (x1, y1), (x2, y2), (255, 0, 0), 2)
#                 cv2.putText(frame, label, (x1, y1 - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (255, 0, 0), 2)

#                 # Print debug information
#                 print(f'Detected {label} at [{x1}, {y1}, {x2}, {y2}] with score {pred_scores[i]}')

#                 # Save detection to MongoDB
#                 detection = {
#                     "class": model.names[int(pred_classes[i])],
#                     "timestamp": dt.datetime.now(),
#                     "day": dt.datetime.now().day,
#                     "month": dt.datetime.now().month,
#                     "year": dt.datetime.now().year
#                 }
#                 try:
#                     collection.insert_one(detection)
#                     print(f'Detection saved to MongoDB: {detection}')
#                 except Exception as e:
#                     print(f'Error saving detection to MongoDB: {e}')

#             # Encode the frame as JPEG
#             ret, buffer = cv2.imencode('.jpg', frame)

#             if not ret:
#                 continue

#             # Yield the frame as a byte array
#             yield (b'--frame\r\n'
#                    b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')

#     finally:
#         # Release the camera
#         cap.release()

# @app.route('/video_feed')
# def video_feed():
#     return Response(detect_objects(), mimetype='multipart/x-mixed-replace; boundary=frame')

# if __name__ == '__main__':
#     app.run(debug=True)
