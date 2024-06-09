import argon2
from flask import Flask
from markupsafe import escape
from flask import request
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from pymongo import MongoClient
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column
from flask import jsonify
import base64
import os
from flask import Response, flash, redirect, render_template, url_for
from ultralytics import YOLO
from werkzeug.utils import secure_filename
from argon2 import PasswordHasher
from datetime import timedelta,datetime
from datetime import datetime
from datetime import timedelta
from datetime import timezone


from flask_jwt_extended import create_access_token
from flask_jwt_extended import current_user
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
import functools

from flask import Flask, render_template, Response
import cv2
from ultralytics import YOLO
from flask_mail import Mail, Message

import secrets
UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

class Base(DeclarativeBase):
  pass



app = Flask(__name__)
# configure the SQLite database, relative to the app instance folder
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:123@127.0.0.1/myflask"
app.config['MAIL_SERVER'] ='smtp.gmail.com'

app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "riyanbayu0102@gmail.com"
app.config['MAIL_PASSWORD'] = "wcfxyxojmhutvccl"

db = SQLAlchemy(model_class=Base)
db.init_app(app)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Setup the Flask-JWT-Extended extension
mail = Mail(app)

# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
timedelta(days=1)
jwt = JWTManager(app)

class User(db.Model): #User class inherit Model class
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(unique=True)
    name: Mapped[str]
    password: Mapped[str]
    avatar: Mapped[str] = mapped_column(nullable=True)
    created_at: Mapped[str]
    updated_at: Mapped[str]
    is_verified: Mapped[bool] = mapped_column(default=False)
    verification_token: Mapped[str] = mapped_column(nullable=True)
    reset_token: Mapped[str] = mapped_column(nullable=True)
    reset_token_expiry: Mapped[datetime] = mapped_column(nullable=True)

class ApiKey(db.Model): #User class inherit Model class
    api_key: Mapped[str] = mapped_column(primary_key=True)

# @jwt.user_identity_loader
# def user_identity_lookup(user):
#     return user.id

# @jwt.user_lookup_loader
# def user_lookup_callback(_jwt_header, jwt_data):
#     id = jwt_data["sub"]
#     return User.query.filter_by(id=id).one_or_none()

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()

@app.route("/user", methods=['GET','POST','PUT','DELETE'])
@jwt_required()
def user():
    if request.method == 'POST':
        dataDict = request.get_json() #It return dictionary.
        email = dataDict["email"]
        name = dataDict["name"]
        password = dataDict["password"]
        
        hashed_password = PasswordHasher().hash(password)
        
        created_at= datetime.now()
        updated_at= datetime.now()
        
        user = User(
            email= email,
            name = name,
            password=hashed_password,
            created_at = created_at,
            updated_at = updated_at
        )
        db.session.add(user)
        db.session.commit()
        
        user_id = user.id
        res = {
            "id": user_id,
            "name" : user.name,
            "email" : user.email
        }
        
        return {
            "data": res,
            "message": "Successfull",
        },200
        
        
    elif request.method == 'PUT':
        dataDict = request.get_json()
        id = dataDict["id"]
        email = dataDict["email"]
        name = dataDict["name"]
        
        if not id:
            return {
                "message": "ID required"
            },400
        
        row = db.session.execute(
            db.select(User) #Select from user model
            .filter_by(id=id) #where ID=1  by id
            ).scalar_one() # Return a list of rows.
        if "email" in dataDict : 
            row.email = dataDict["email"]
            
        if "name" in dataDict :
            row.name = dataDict["name"]
        
        row.updated_at=datetime.now()

        db.session.commit()
        return {
            "message": "Success update data user"
        }, 200
        
    elif request.method == 'DELETE':
        dataDict = request.get_json() #It return dictionary.
        id = dataDict["id"]
        
        if not id:
            return {
                "message": "ID required"
            },400
        
        row = db.session.execute(
            db.select(User) #Select from user model
            .filter_by(id=id) #where ID=1  by id
            ).scalar_one() # Return a list of rows.
        
        db.session.delete(row)
        db.session.commit()
        return {
            "message": "Successfull!"
        }, 200
    else : #GET
        rows = db.session.execute(
            db.select(User).order_by(User.id)
            ).scalars()
        
        users =[]
        for row in rows:
            users.append({
                "id" : row.id,
                "email" : row.email,
                "name" : row.name,
                "avatar" : row.avatar
            })
        return {
            "data" : users,
            "message" : "Sukses menampilkan data user"
        },200
@app.post('/signup')
def signup():
    try:
        data = request.form
        email, name, password = data.get("email"), data.get("name"), data.get("password")

        if not email:
            return jsonify(message="Email harus diisi"), 400
        if User.query.filter_by(email=email).first():
            return jsonify(error=True, message="Email sudah terdaftar. Silakan gunakan email lain."), 400

        hashed_password = PasswordHasher().hash(password)
        verification_token = secrets.token_urlsafe(32)
        
        created_at = datetime.utcnow()
        updated_at = created_at
        
        new_user = User(
            email=email,
            name=name,
            password=hashed_password,
            created_at=created_at,
            updated_at=updated_at,
            verification_token=verification_token
        )
        
        db.session.add(new_user)
        db.session.commit()

        confirmation_url = url_for('confirm_email', token=verification_token, _external=True)
        msg = Message(subject="Verify your email", sender="noreply@app.com", recipients=[email])
        msg.html = render_template("verify-email.html", confirmation_url=confirmation_url)

        mail.send(msg)
        
        return jsonify(message="Sukses melakukan registrasi. Silakan cek email untuk konfirmasi.", error=False), 201
    except Exception as e:
        print(e)
        return jsonify(message=f"Error {e}"), 500

@app.route('/confirm_email/<token>')
def confirm_email(token):
    user = User.query.filter_by(verification_token=token).first_or_404()
    if user.is_verified:
        return jsonify(message="Account already verified."), 200
    user.is_verified = True
    user.verification_token = None
    user.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify(message="Email verified successfully."), 200

def send_email(to, subject, body):
    msg = Message(subject, recipients=[to], body=body)
    mail.send(msg)


@app.post("/signin")
def signin():
    email = request.form.get("email")
    password = request.form.get("password")
    
    # Fetch the user by email
    user = db.session.execute(
        db.select(User).filter_by(email=email)
    ).scalar_one()
    
    if not user:
        return jsonify({"message": "Email or password is incorrect!"}), 400

    # Verify the user's password
    try:
        PasswordHasher().verify(user.password, password)
    except:
        return jsonify({"message": "Email or password is incorrect!"}), 400
    
    # Check if the user's email is verified
    if not user.is_verified:
        return jsonify({"message": "Please verify your email before logging in."}), 403
    
    # Generate JWT token
    access_token = create_access_token(identity=user.id)
    
    return jsonify({"access_token": access_token}), 200


@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.form
    email = data.get('email')
    
    user = User.query.filter_by(email=email).first()
    
    if not user:
        return jsonify({"message": "Email not found"}), 404
    
    reset_token = secrets.token_urlsafe(32)
    user.reset_token = reset_token
    user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
    db.session.commit()
    
    reset_url = url_for('reset_password_form', token=reset_token, _external=True)
    msg = Message(subject="Reset Your Password", sender="noreply@app.com", recipients=[email])
    msg.html = render_template("reset-password.html", reset_url=reset_url)
    mail.send(msg)
    
    return jsonify({"message": "Password reset link has been sent to your email"}), 200

@app.route('/reset_password/<token>', methods=['GET'])
def reset_password_form(token):
    user = User.query.filter_by(reset_token=token).first()
    
    if not user or user.reset_token_expiry < datetime.utcnow():
        return jsonify({"message": "Token is invalid or expired"}), 400
    
    return render_template('reset-password-form.html', token=token)

@app.route('/reset_password/<token>', methods=['POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    
    if not user or user.reset_token_expiry < datetime.utcnow():
        return jsonify({"message": "Token is invalid or expired"}), 400
    
    data = request.form
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')
    
    if new_password != confirm_password:
        return jsonify({"message": "Passwords do not match"}), 400
    
    hashed_password = PasswordHasher().hash(new_password)
    
    user.password = hashed_password
    user.reset_token = None
    user.reset_token_expiry = None
    user.updated_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({"message": "Password has been reset successfully"}), 200
       
       

@app.get('/protected')
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    return jsonify(name=user.name, email=user.email,avatar=user.avatar), 200
        

@app.route('/change_password', methods=['PUT'])
@jwt_required()
def change_password():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    current_password = request.form.get("current_password")
    new_password = request.form.get("new_password")
    
    
    if not current_password or not new_password:
        return jsonify({"message": "Current and new passwords are required"}), 400
    
    # Verify current password
    try:
        PasswordHasher().verify(user.password, current_password)
    except:
        return jsonify({"message": "Current password is incorrect"}), 400
    
    # Hash new password
    hashed_password = PasswordHasher().hash(new_password)
    
    # Update user's password
    user.password = hashed_password
    user.updated_at = datetime.now()
    db.session.commit()
    
    return jsonify({"message": "Password updated successfully"}), 200

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
@app.route('/edit_profile', methods=['PUT'])
@jwt_required()
def edit_profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    data = request.form
    
    if 'name' in data:
        user.name = data['name']
    
    if 'email' in data:
        user.email = data['email']
    
    if 'file' in request.files:
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            user.avatar = url_for('static', filename='uploads/' + filename, _external=True)

    user.updated_at = datetime.now()
    db.session.commit()

    return jsonify({
        "message": "Profile updated successfully",
    }), 200

mongo_client = MongoClient('mongodb://localhost:27017/')
mongo_db = mongo_client['latihan']
mongo_collection = mongo_db['bayu']

@app.route('/')
def index():
    return render_template('video.html')

def detect_objects():
    model = YOLO('model/best.pt')
    cap = cv2.VideoCapture(0)
    try:
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            frame = cv2.flip(frame, 1)
            results = model(frame)
            pred_boxes = results[0].boxes.xyxy.cpu().numpy()
            pred_scores = results[0].boxes.conf.cpu().numpy()
            pred_classes = results[0].boxes.cls.cpu().numpy()
            for i, box in enumerate(pred_boxes):
                x1, y1, x2, y2 = map(int, box)
                label = f'{model.names[int(pred_classes[i])]} {pred_scores[i]:.2f}'
                cv2.rectangle(frame, (x1, y1), (x2, y2), (255, 0, 0), 2)
                cv2.putText(frame, label, (x1, y1 - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (255, 0, 0), 2)
                detection = {
                    "class": model.names[int(pred_classes[i])],
                    "timestamp": datetime.now(),
                    "day": datetime.now().day,
                    "month": datetime.now().month,
                    "year": datetime.now().year
                }
                try:
                    mongo_collection.insert_one(detection)
                    print(f'Detection saved to MongoDB: {detection}')
                except Exception as e:
                    print(f'Error saving detection to MongoDB: {e}')
            ret, buffer = cv2.imencode('.jpg', frame)
            if not ret:
                continue
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')
    finally:
        cap.release()

@app.route('/video_feed')
def video_feed():
    return Response(detect_objects(), mimetype='multipart/x-mixed-replace; boundary=frame')

if __name__ == '__main__':
    #   app.run(debug=True)
      app.run(host='192.168.202.81', port='5000', debug=True)

# @app.post('/signup')
# def signup():
#     name = request.form.get("name")
#     email = request.form.get("email")
#     password = request.form.get("password")
#     # re_password = request.form.get("re_password")
    
#     created_at= datetime.now()
#     updated_at= datetime.now()
    
#     # Memeriksa apakah password sama dengan re_password
#     # if password != re_password:
#     #     return {
#     #         "message" : "Password tidak sama!"
#     #     }, 400
    
#     # Memeriksa apakah email terisi
#     if not email:
#         return {
#             "message" : "Email harus diisi"
#         }, 400
        
#     # Mengecek apakah email sudah terdaftar sebelumnya
#     existing_user = User.query.filter_by(email=email).first()
#     if existing_user:
#         return {
#             "error" : True,
#             "message": "Email sudah terdaftar. Silakan gunakan email lain."
#         }, 400
        
#     # Menghash password menggunakan Argon2
#     hashed_password = PasswordHasher().hash(password)
    
#     # Membuat objek User dengan menggunakan properti yang sesuai
#     # Pastikan properti ini sesuai dengan definisi model
#     new_user = User(
#         email=email,
#         name=name,
#         password=hashed_password,  
#         created_at=created_at,
#         updated_at=updated_at
#     )
#     db.session.add(new_user)
#     db.session.commit()
    
#     # res = {
#     #     "id": new_user.id,
#     #     "name" : name,
#     #     "email" : email,
#     # }
#     return {
#         # "data" : res,
#         "message" : "Sukses melakukan registrasi",
#         "error": False
        
#     },201   
 

# @app.post("/signin")
# def signin():
#     # #Mengambil the Authorization header
#     # base64Str = request.headers.get('Authorization')
#     # print("base64 :", base64Str)
#     # base64Str = base64Str[6:] # hapus "Basic" string
    
#     # #Mulai Base64 Decode
#     # base64Bytes = base64Str.encode('ascii')
#     # messageBytes = base64.b64decode(base64Bytes)
#     # pair = messageBytes.decode('ascii')
#     # #Akhir Base64 Decode
    
#     # email, password = pair.split(":")
    
#     email = request.form.get("email")
#     password = request.form.get("password")
    
#     # Memanggil data email pada database
#     user = db.session.execute(
#         db.select(User)
#         .filter_by(email=email)
#     ).scalar_one()
    
#     if not user or not PasswordHasher().verify(user.password, password):
#         return {
#             "message": "wrong password or email!"
#         },400
#     #End Authentication    
    
#     #Start Generate JWT Token
#     access_token = create_access_token(identity=user.id)
#     #End Generate JWT Token
#     return {
#         "access_token" : access_token,
#     },200
    
# @app.get("/myprofile")
# @jwt_required()
# def profile():
#     current_user = get_jwt_identity()
    
#     return {
#         "id" : current_user.id,
#         "email" : current_user.email,
#         "name" : current_user.name,
        
#     }

# @app.get("/siapa")
# @jwt_required()
# def protected():
#     # We can now access our sqlalchemy User object via `current_user`.
#     return jsonify(
#         id=current_user.id,
#         email=current_user.email,
#           name=current_user.name,
#     )


# @app.route("/")
# def hello_world():
#     return{
#         "message" : "hello_world",
#     },200


# @app.route('/user/<username>')
# def show_user_profile(username):
#     # show the user profile for that user
#    return {
#          "message" : f"hello, {username}!"
#     },200

# @app.route('/post/<int:post_id>')
# def show_post(post_id):
#     # show the post with the given id, the id is an integer
#     return f'Post {post_id}'

# app.route('/path/<path:subpath>')
# def show_subpath(subpath):
#     # show the subpath after /path/
#     return f'Subpath {escape(subpath)}'

# @app.route('/upload', methods=['GET', 'POST'])
# def upload_file():
#     if request.method == 'POST':
#         f = request.files['image']
#         f.save('image.jpg')
#     return{
#         "message" : "succes",
    # },200