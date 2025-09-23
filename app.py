from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import base64
import hmac
import hashlib
import os
import random
import re
import secrets
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from itsdangerous import URLSafeTimedSerializer
from PIL import Image as PILImage
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.exceptions import RateLimitExceeded

# 1. 애플리케이션 및 기본 설정
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_for_local_dev')
app.config['FINGERPRINT_SECRET'] = os.environ.get('FINGERPRINT_SECRET', 'local_fingerprint_secret')
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_TIME_LIMIT'] = int(os.environ.get('WTF_CSRF_TIME_LIMIT', 3600))
app.config['WTF_CSRF_CHECK_DEFAULT'] = True
app.config['WTF_CSRF_ENABLED'] = True

if os.environ.get('ENABLE_SECURE_COOKIES', '1') == '1':
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE=os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax'),
        REMEMBER_COOKIE_SECURE=True,
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SAMESITE=os.environ.get('REMEMBER_COOKIE_SAMESITE', 'Lax')
    )
db = SQLAlchemy(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
csrf = CSRFProtect(app)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=os.environ.get('RATELIMIT_STORAGE_URI', 'memory://'),
    default_limits=[]
)

# 2. 파일 시스템 설정
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['STATIC_FOLDER'] = os.path.join(BASE_DIR, 'static')
default_extensions = {'png', 'jpg', 'jpeg', 'gif'}
configured_extensions = os.environ.get('ALLOWED_UPLOAD_EXTENSIONS')
if configured_extensions:
    app.config['ALLOWED_UPLOAD_EXTENSIONS'] = {
        ext.strip().lower() for ext in configured_extensions.split(',') if ext.strip()
    }
else:
    app.config['ALLOWED_UPLOAD_EXTENSIONS'] = default_extensions

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
    secret = app.config['FINGERPRINT_SECRET'].encode('utf-8')
    salt = secrets.token_bytes(16)
    salt_bits = ''.join(f'{byte:08b}' for byte in salt)

    data_bytes = text_to_embed.encode('utf-8')
    length_bits = f'{len(data_bytes):016b}'
    data_bits = ''.join(f'{byte:08b}' for byte in data_bytes)

    try:
        img = PILImage.open(image_path).convert('RGB')
        flat_channels = [channel for pixel in img.getdata() for channel in pixel]

        prefix_bits = salt_bits + length_bits
        total_bits = len(prefix_bits) + len(data_bits)

        if total_bits > len(flat_channels):
            raise ValueError("이미지가 너무 작습니다.")

        # Embed salt + length sequentially for deterministic extraction
        for index, bit in enumerate(prefix_bits):
            flat_channels[index] = (flat_channels[index] & ~1) | int(bit)

        # Scatter actual payload bits using keyed PRNG for resilience
        seed_material = hmac.new(secret, salt, hashlib.sha256).digest()
        seed = int.from_bytes(seed_material[:8], 'big')
        rng = random.Random(seed)

        available_indexes = list(range(len(prefix_bits), len(flat_channels)))
        rng.shuffle(available_indexes)
        target_indexes = available_indexes[:len(data_bits)]

        for bit, idx in zip(data_bits, target_indexes):
            flat_channels[idx] = (flat_channels[idx] & ~1) | int(bit)

        # Reconstruct image
        reconstructed = [tuple(flat_channels[i:i+3]) for i in range(0, len(flat_channels), 3)]
        img.putdata(reconstructed)

        base, ext = os.path.splitext(image_path)
        output_path = f"{base}_fp{ext}"
        img.save(output_path)
        return output_path
    except Exception as e:
        print(f"Error embedding: {e}")
        return None


def extract_fingerprint(image_path):
    secret = app.config['FINGERPRINT_SECRET'].encode('utf-8')
    salt_bit_length = 16 * 8
    length_bit_length = 16

    try:
        img = PILImage.open(image_path).convert('RGB')
        flat_channels = [channel for pixel in img.getdata() for channel in pixel]

        if len(flat_channels) < salt_bit_length + length_bit_length:
            return None

        salt_bits = ''.join(str(flat_channels[i] & 1) for i in range(salt_bit_length))
        salt_bytes = bytes(int(salt_bits[i:i+8], 2) for i in range(0, len(salt_bits), 8))

        length_bits = ''.join(str(flat_channels[salt_bit_length + i] & 1) for i in range(length_bit_length))
        payload_length = int(length_bits, 2)

        if payload_length <= 0:
            return None

        total_bits_needed = payload_length * 8

        seed_material = hmac.new(secret, salt_bytes, hashlib.sha256).digest()
        seed = int.from_bytes(seed_material[:8], 'big')
        rng = random.Random(seed)

        available_indexes = list(range(salt_bit_length + length_bit_length, len(flat_channels)))
        rng.shuffle(available_indexes)
        target_indexes = available_indexes[:total_bits_needed]

        data_bits = ''.join(str(flat_channels[idx] & 1) for idx in target_indexes)
        data_bytes = bytes(int(data_bits[i:i+8], 2) for i in range(0, len(data_bits), 8))
        return data_bytes.decode('utf-8')
    except Exception as e:
        print(f"Error extracting: {e}")
        return None


def generate_fingerprint_token(username: str) -> str:
    secret = app.config['FINGERPRINT_SECRET'].encode('utf-8')
    nonce = secrets.token_bytes(8)
    timestamp = int(datetime.utcnow().timestamp())
    timestamp_bytes = timestamp.to_bytes(8, 'big')
    signature = hmac.new(secret, nonce + timestamp_bytes + username.encode('utf-8'), hashlib.sha256).digest()
    payload = nonce + timestamp_bytes + signature
    return base64.urlsafe_b64encode(payload).decode('utf-8')


def resolve_fingerprint_owner(token: str):
    secret = app.config['FINGERPRINT_SECRET'].encode('utf-8')
    try:
        raw = base64.urlsafe_b64decode(token.encode('utf-8'))
        if len(raw) != 48:
            return None, None
        nonce = raw[:8]
        timestamp_bytes = raw[8:16]
        signature = raw[16:]
        for user in User.query.all():
            expected = hmac.new(secret, nonce + timestamp_bytes + user.username.encode('utf-8'), hashlib.sha256).digest()
            if hmac.compare_digest(signature, expected):
                timestamp = int.from_bytes(timestamp_bytes, 'big')
                issued_at = datetime.fromtimestamp(timestamp)
                return user.username, issued_at
    except Exception as e:
        print(f"Error resolving fingerprint: {e}")
    return None, None

@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    flash('보안 검증이 만료되었거나 잘못되었습니다. 페이지를 새로고침한 뒤 다시 시도해 주세요.', 'error')
    return redirect(request.referrer or url_for('home')), 400

@app.errorhandler(RateLimitExceeded)
def handle_rate_limit(error):
    flash('요청이 너무 자주 발생했습니다. 잠시 후 다시 시도해 주세요.', 'error')
    target = request.referrer
    if not target:
        if request.endpoint in {'upload_file', 'verify_fingerprint'}:
            target = url_for(request.endpoint)
        else:
            target = url_for('home')
    return redirect(target), 429

def allowed_file(filename):
    allowed = app.config.get('ALLOWED_UPLOAD_EXTENSIONS', default_extensions)
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed

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
@limiter.limit("5 per minute", methods=['POST'], per_method=True, error_message='업로드 요청은 분당 5회로 제한됩니다.')
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

            token = generate_fingerprint_token(session['username'])
            fingerprinted_path = embed_fingerprint(original_file_path, token)

            if fingerprinted_path:
                fingerprinted_filename = os.path.basename(fingerprinted_path)
                new_image = Image(filename=fingerprinted_filename,
                                  fingerprint_text=token,
                                  user_id=session['user_id'])
                db.session.add(new_image)
                db.session.commit()
                return redirect(url_for('upload_success', filename=fingerprinted_filename, original=original_filename))
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
@limiter.limit("10 per minute", methods=['POST'], per_method=True, error_message='검증 요청은 분당 10회로 제한됩니다.')
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
            token = extract_fingerprint(temp_path)
            os.remove(temp_path)
            if not token:
                flash('숨겨진 데이터가 감지되지 않았습니다.', 'error')
                return redirect(request.url)

            owner, issued_at = resolve_fingerprint_owner(token)
            verification = {
                'token': token,
                'owner': owner,
                'issued_at': issued_at
            }
            return render_template('verify.html', result=verification)
    return render_template('verify.html', result=None)

@app.route('/success/<filename>')
def upload_success(filename):
    original = request.args.get('original')
    return render_template('result.html', filename=filename, original_filename=original)

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
