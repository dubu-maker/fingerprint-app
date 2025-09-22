from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from itsdangerous import URLSafeTimedSerializer
from PIL import Image

# 1. 애플리케이션 및 기본 설정
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_for_local_dev')
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# 2. 파일 시스템 설정
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['STATIC_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# 3. 데이터베이스 모델 정의
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    plan = db.Column(db.String(20), nullable=False, default='basic')
    images = db.relationship('Image', backref='author', lazy=True)

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    fingerprint_text = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# 4. 헬퍼 함수
def embed_fingerprint(image_path, text_to_embed):
    try:
        img = Image.open(image_path).convert('RGB')
        width, height = img.size
        binary_text = ''.join(format(ord(char), '08b') for char in text_to_embed) + '11111111'
        
        if len(binary_text) > width * height * 3:
            raise ValueError("이미지가 너무 작습니다.")

        data_index = 0
        pixels = img.load()
        for y in range(height):
            for x in range(width):
                pixel = list(pixels[x, y])
                for i in range(3):
                    if data_index < len(binary_text):
                        pixel[i] = pixel[i] & ~1 | int(binary_text[data_index])
                        data_index += 1
                pixels[x, y] = tuple(pixel)
                if data_index >= len(binary_text):
                    base, ext = os.path.splitext(image_path)
                    output_path = f"{base}_fp{ext}"
                    img.save(output_path)
                    return output_path
        return None
    except Exception as e:
        print(f"Error embedding: {e}")
        return None

def extract_fingerprint(image_path):
    try:
        img = Image.open(image_path).convert('RGB')
        pixels = img.load()
        binary_text = ""
        limit = 2000 
        
        for y in range(img.height):
            for x in range(img.width):
                pixel = pixels[x, y]
                for i in range(3):
                    binary_text += str(pixel[i] & 1)
                    if len(binary_text) >= limit: break
                if len(binary_text) >= limit: break
            if len(binary_text) >= limit: break
        
        all_bytes = [binary_text[i: i+8] for i in range(0, len(binary_text), 8)]
        decoded_text = ""
        for byte in all_bytes:
            if byte == '11111111':
                return decoded_text
            decoded_text += chr(int(byte, 2))
        return "종료 신호를 찾을 수 없거나 데이터가 없습니다."
    except Exception as e:
        print(f"Error extracting: {e}")
        return "추출 중 오류 발생"

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 5. 라우트 (웹 페이지 로직)
@app.route('/')
def home():
    video_token = None
    if session.get('user_id') and session.get('role') != 'admin':
        video_token = s.dumps('print.mp4')

    if session.get('role') == 'admin':
        user_count = User.query.count()
        recent_users = User.query.order_by(User.id.desc()).limit(5).all()
        return render_template('home.html', user_count=user_count, recent_users=recent_users, video_token=video_token)
    
    return render_template('home.html', video_token=video_token)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        username_regex = re.compile(r'^[a-zA-Z0-9_]{4,20}$')
        if not username_regex.match(username):
            flash('사용자 이름은 4~20자의 영문, 숫자, 언더바(_)만 사용할 수 있습니다.', 'error')
            return redirect(url_for('register'))
        
        password_regex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
        if not password_regex.match(password):
            flash('비밀번호는 최소 8자 이상이며, 대/소문자, 숫자, 특수문자(@$!%*?&)를 각각 하나 이상 포함해야 합니다.', 'error')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('이미 존재하는 사용자 이름입니다.', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        role = 'admin' if User.query.count() == 0 else 'user'
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        
        flash(f"'{username}' 계정 가입 성공! 이제 로그인하세요.")
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session['plan'] = user.plan
            return redirect(url_for('home'))
        else:
            flash('사용자 이름이 없거나 비밀번호가 틀렸습니다.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('성공적으로 로그아웃되었습니다.')
    return redirect(url_for('home'))

@app.route('/users')
def show_users():
    if session.get('role') == 'admin':
        all_users = User.query.all()
        return render_template('users.html', users=all_users)
    else:
        flash('접근 권한이 없습니다.', 'error')
        return redirect(url_for('login'))
    
@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if session.get('role') != 'admin':
        flash('삭제 권한이 없습니다.', 'error')
        return redirect(url_for('home'))
    user_to_delete = User.query.get_or_404(user_id)
    db.session.delete(user_to_delete)
    db.session.commit()
    flash(f'사용자 ID {user_id}가 성공적으로 삭제되었습니다.')
    return redirect(url_for('show_users'))

@app.route('/update_plan/<int:user_id>', methods=['POST'])
def update_plan(user_id):
    if session.get('role') != 'admin':
        flash('권한이 없습니다.', 'error')
        return redirect(url_for('home'))
    new_plan = request.form.get('plan')
    if new_plan not in ['basic', 'premium']:
        flash('잘못된 등급입니다.', 'error')
        return redirect(url_for('show_users'))
    user_to_update = User.query.get_or_404(user_id)
    user_to_update.plan = new_plan
    db.session.commit()
    flash(f'{user_to_update.username} 사용자의 등급이 {new_plan}(으)로 변경되었습니다.')
    return redirect(url_for('show_users'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'username' not in session:
        flash('이미지를 업로드하려면 먼저 로그인하세요.', 'error')
        return redirect(url_for('login'))
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('파일이 없습니다.')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('선택된 파일이 없습니다.')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            original_filename = secure_filename(file.filename)
            original_file_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
            file.save(original_file_path)
            
            fingerprinted_path = embed_fingerprint(original_file_path, session['username'])
            
            if fingerprinted_path:
                fingerprinted_filename = os.path.basename(fingerprinted_path)
                new_image = Image(filename=original_filename, 
                                  fingerprint_text=session['username'], 
                                  user_id=session['user_id'])
                db.session.add(new_image)
                db.session.commit()
                flash(f"'{original_filename}' 파일에 핑거프린트를 삽입했습니다.")
                return redirect(url_for('upload_success', filename=fingerprinted_filename))
            else:
                flash('핑거프린트 삽입에 실패했습니다.', 'error')
                return redirect(request.url)
        else:
            flash('허용된 파일 형식이 아닙니다. (png, jpg, jpeg, gif)', 'error')
            return redirect(request.url)
    return render_template('upload.html')

@app.route('/my-images')
def my_images():
    if 'user_id' not in session:
        flash('먼저 로그인하세요.', 'error')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('my_images.html', images=user.images)

@app.route('/verify', methods=['GET', 'POST'])
def verify_fingerprint():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('파일이 없습니다.', 'error')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('선택된 파일이 없습니다.', 'error')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{filename}")
            file.save(temp_path)
            result = extract_fingerprint(temp_path)
            os.remove(temp_path)
            return render_template('verify.html', result=result)
    return render_template('verify.html')

@app.route('/success/<filename>')
def upload_success(filename):
    return render_template('result.html', filename=filename)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/serve_video/<token>')
def serve_video(token):
    if 'user_id' not in session:
        return "Access Denied", 403
    try:
        filename = s.loads(token, max_age=30)
    except Exception:
        return "Invalid or expired link.", 403

    if filename != 'print.mp4':
        return "Access Denied", 403

    return send_from_directory(os.path.join(app.config['STATIC_FOLDER'], 'videos'), filename)

# 6. 애플리케이션 실행
if __name__ == '__main__':
    app.run(debug=True)
