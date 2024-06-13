import base64
import os
import secrets
from urllib.parse import urljoin
from flask_mail import Mail, Message
from itsdangerous import SignatureExpired, URLSafeTimedSerializer
from flask import Response, redirect, render_template, url_for
from pymongo import MongoClient
import requests
from werkzeug.utils import secure_filename

from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped, mapped_column
from flask import jsonify

from argon2 import PasswordHasher

from datetime import timedelta,datetime

from flask_jwt_extended import *

import functools

from flask_pymongo import PyMongo

from detect_count import count_object, get_data

class Base(DeclarativeBase): 
    pass #Blank body class, but "Base" class inherits "DeclarativeBase" class


UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


# Instantiate Flask
app = Flask(__name__) 
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:@127.0.0.1/myflask"  #"mysql://username:password@localhost/databasename"  

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Instantiate SQLALchemy
db = SQLAlchemy(model_class=Base) 
db.init_app(app)

# MongoDB configuration
app.config["MONGO_URI"] = "mongodb://localhost:27017/object_counter_db"
mongo = PyMongo(app)

# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
jwt = JWTManager(app)

# Setup the Mail-Server
app.config['MAIL_SERVER'] ='smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "maulana29.rizqi@gmail.com"
app.config['MAIL_PASSWORD'] = "wtblqfxrlnjijnhr"

mail = Mail(app)

app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SECURITY_PASSWORD_SALT'] = 'your_password_salt_here'


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

class ApiKey(db.Model): #User class inherit Model class
    api_key: Mapped[str] = mapped_column(primary_key=True)
    

class Artikel(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    judul: Mapped[str]
    konten: Mapped[str]
    
class Gambar(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    pathname: Mapped[str]
    deskripsi: Mapped[str]
   

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()

def api_key_required(func):
    @functools.wraps(func)
    def check_api_key():
        apiKey = request.headers.get('x-api-key')
        apiKey = ApiKey.query.filter_by(api_key=apiKey).one_or_none()
        if apiKey:
            return func()
        else:
            return {"message": "Please provide a correct API key"}, 400
    return check_api_key

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
        

@app.post('/register')
@api_key_required
def register():
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

@app.post('/signup')
def signup():
    name = request.form.get("name")
    email = request.form.get("email")
    password = request.form.get("password")
    
    created_at= datetime.now()
    updated_at= datetime.now()
    
    # Memeriksa apakah email terisi
    if not email:
        return {
            "message" : "Email harus diisi"
        }, 400
        
    # Mengecek apakah email sudah terdaftar sebelumnya
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return {
            "error" : True,
            "message": "Email sudah terdaftar. Silakan gunakan email lain."
        }, 400
        
    if len(password) < 8:
        return {
            "error" : True,
            "message": "Password harus terdiri dari minimal 8 karakter."
        }, 400
    
    # Menghash password menggunakan Argon2
    hashed_password = PasswordHasher().hash(password)
    
    # Pastikan properti ini sesuai dengan definisi model
    new_user = User(
        email=email,
        name=name,
        password=hashed_password,  
        created_at=created_at,
        updated_at=updated_at
    )
    db.session.add(new_user)
    db.session.commit()
    
    return {

        "message" : "Sukses melakukan registrasi",
        "error": False
        
    },201   
        
    
@app.post("/login")
def login():
    
    #catch the Authorization header
    base64Str = request.headers.get('Authorization')
    base64Str = base64Str[6:] # hapus "Basic" string
    
    #Mulai Base64 Decode
    base64Bytes = base64Str.encode('ascii')
    messageBytes = base64.b64decode(base64Bytes)
    pair = messageBytes.decode('ascii')
    #Akhir Base64 Decode
    
    email, password = pair.split(":")
    # Memanggil data email pada database
    user = db.session.execute(
        db.select(User)
        .filter_by(email=email)
    ).scalar_one()
    
    try:
        PasswordHasher().verify(user.password, password)
    except:
        return jsonify({"message": "Email or password is incorrect!"}), 400
    
    # Check if the user's email is verified
    if not user.is_verified:
        return jsonify({"message": "Please verify your email before logging in."}), 403
    #End Authentication    
    #Start Generate JWT Token
    access_token = create_access_token(identity=user.id)
    #End Generate JWT Token
    return {
        "access_token" : access_token,
    },200


@app.post("/signin")
def signin():
    email = request.form.get("email")
    password = request.form.get("password")
    
    # Memanggil data email pada database
    user = db.session.execute(
        db.select(User)
        .filter_by(email=email)
    ).scalar_one()
    
    if not user or not PasswordHasher().verify(user.password, password):
        return {
            "message": "wrong password or email!"
        },400
    #End Authentication    
    #Start Generate JWT Token
    access_token = create_access_token(identity=user.id)
    #End Generate JWT Token
    return {
        "access_token" : access_token,
    },200
    
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


from itsdangerous import URLSafeTimedSerializer

# Setup the URLSafeTimedSerializer
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def generate_password_reset_token(email):
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_password_reset_token(token, expiration=3600):
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=expiration)
    except SignatureExpired:
        return False
    return email

@app.post('/reset_password_request')
def reset_password_request():
    email = request.form.get("email")
    
    if not email:
        return jsonify(message="Email harus diisi"), 400
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify(message="Email tidak ditemukan"), 404
    
    token = generate_password_reset_token(email)
    reset_url = url_for('reset_password', token=token, _external=True)
    
    # Send reset email
    msg = Message(subject="Password Reset Request", sender="noreply@app.com", recipients=[email])
    msg.html = render_template("reset_password.html", reset_url=reset_url)
    mail.send(msg)
    
    return jsonify(message="Silakan cek email untuk mengatur ulang kata sandi Anda."), 200

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = confirm_password_reset_token(token)
    except:
        return jsonify(message="Tautan reset password tidak valid atau telah kedaluwarsa."), 400
    
    if request.method == 'POST':
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")
        
        if not new_password or not confirm_password:
            return jsonify(message="Password harus diisi"), 400
        
        if new_password != confirm_password:
            return jsonify(message="Password tidak sama"), 400
        
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify(message="User tidak ditemukan"), 404
        
        hashed_password = PasswordHasher().hash(new_password)
        user.password = hashed_password
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify(message="Password berhasil diatur ulang."), 200
    
    return render_template('reset_password_form.html', token=token)


@app.get('/protected')
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    user = db.session.get(User, current_user_id)
    return jsonify(name=user.name, email=user.email,avatar=user.avatar), 200
    

@app.route("/artikel", methods=['GET','POST'])
# @api_key_required
# @jwt_required()
def artikel():
    if request.method == 'POST':
        dataDict = request.get_json()  # Menggunakan request.form untuk mendapatkan data formulir dari permintaan
        judul = dataDict["judul"]
        konten = dataDict["konten"]
        
        artikel = Artikel(
            judul=judul,
            konten=konten,
            
        )
        db.session.add(artikel)
        db.session.commit()
        
        return {
            "message": "Artikel berhasil dibuat",
            "data": {"judul": judul, "konten": konten}
        }, 200 
    else : #GET
        rows = db.session.execute(
            db.select(Artikel).order_by(Artikel.id)
            ).scalars()
        
        artikels =[]
        for row in rows:
            artikels.append({
                "id" : row.id,
                "judul" : row.judul,
                "konten" : row.konten,
            })
        return artikels, 200

@app.route("/artikel/<id>", methods=['PUT','DELETE'])
# @jwt_required()
def detailartikel(id):
    if request.method == 'PUT':
        dataDict = request.get_json() #It return dictionary.
        judul = dataDict["judul"]
        konten = dataDict["konten"]
        
        artikel_id = Artikel.query.filter_by(id=id).first()

        if not artikel_id:
            return {
                "message": "ID tidak tersedia"
            },400
        
        row = db.session.execute(
            db.select(Artikel) #Select from user model
            .filter_by(id=id) #where ID=1  by id
            ).scalar_one() # Return a list of rows.
        
        row.judul = judul
        row.konten = konten
            
        db.session.commit()
        
        return {
            "message": "Success update article!"
        }, 200  
    else:
                
        if not id:
            return {
                "message": "ID required"
            },400
            
        row = db.session.execute(
            db.select(Artikel) #Select from user model
            .filter_by(id=id) #where ID=1  by id
            ).scalar_one() # Return a list of rows.

        
        db.session.delete(row)
        db.session.commit()
        return {
            "message": "Succes menghapus data artikel!"
        }, 200

        
@app.route("/user/<id>", methods=['GET','PUT','DELETE'])
# @jwt_required()
def detailUser(id):
    
    if request.method == 'PUT':
        dataDict = request.get_json()
        name = dataDict["name"]
        email = dataDict["email"]
        password = dataDict["password"]
        
        hashed_password = PasswordHasher().hash(password)
        
        if not id:
            return {
                "message": "ID required"
            },400
        
        row = db.session.execute(
            db.select(User) #Select from user model
            .filter_by(id=id) #where ID=1  by id
            ).scalar_one() # Return a list of rows.
        
        row.name = name
        row.email = email
        row.password = hashed_password
        row.updated_at=datetime.now()
        
        db.session.commit()
        return {
            "message": "Success update data user"
        }, 200
        
    elif request.method == 'DELETE':
        
        user_id = User.query.filter_by(id=id).first()
        if not user_id:
            return {
                "error": True,
                "message": "ID diperlukan"
            }, 400
        
        row = db.session.execute(
            db.select(User) #Select from user model
            .filter_by(id=id) #where ID=1  by id
            ).scalar_one() # Return a list of rows.
        
        db.session.delete(row)
        db.session.commit()
        return {
            "message": "Suksek Menghapus Data!"
        }, 200
        
    else : #GET
        
        user_id = User.query.filter_by(id=id).first()
        if not user_id:
            return {
                "error": True,
                "message": "ID diperlukan"
            }, 400

        rows = db.session.execute(
            db.select(User)
            .filter_by(id=id)
            ).scalar_one()
        
        user_data = {
            "id": rows.id,
            "email": rows.email,
            "name": rows.name,
            "created_at" : rows.created_at,
            "updated_at" : rows.updated_at
        }
        
        return {
            "data" : user_data,
            "message" : "Sukses menampilkan data user by id"
        },200
        
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
            
@app.route('/edit_profile', methods=['PUT'])
@jwt_required()
def edit_profile():
    current_user_id = get_jwt_identity()
    user = db.session.get(User, current_user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    data = request.form if request.form else request.json
    
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
    

# Route for visualization page
@app.route('/visualization')
def visualization():
    return render_template('visualization.html')


# Realtime Object Detection & Counting
@app.route('/realtime')
def index():
    return render_template('index.html')

@app.route('/video_feed')
def video_feed():
    return Response(count_object(), mimetype='multipart/x-mixed-replace; boundary=frame')


# Konfigurasi MongoDB
client = MongoClient('mongodb://localhost:27017/')
db_mongo = client['object_counter_db']  # Ganti dengan nama database Anda
collection = db_mongo['detections']  # Ganti dengan nama koleksi Anda

@app.route('/history', methods=['GET'])
def history():
    return Response(get_data())


if __name__ == '__main__':
    app.run(host='192.168.65.85', port=5000, debug=True)