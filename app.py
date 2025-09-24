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
from pathlib import Path

import cv2
import numpy as np
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from itsdangerous import URLSafeTimedSerializer
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
try:
    from flask_limiter.errors import RateLimitExceeded
except ImportError:
    from limits.errors import RateLimitExceeded
from werkzeug.middleware.proxy_fix import ProxyFix

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SQLITE_PATH = os.environ.get('DEFAULT_SQLITE_PATH', os.path.join(BASE_DIR, 'database.db'))

# 1. 애플리케이션 및 기본 설정
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_for_local_dev')
app.config['FINGERPRINT_SECRET'] = os.environ.get('FINGERPRINT_SECRET', 'local_fingerprint_secret')
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

if not DATABASE_URL:
    sqlite_path = Path(DEFAULT_SQLITE_PATH)
    sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    DATABASE_URL = f"sqlite:///{sqlite_path}"

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_TIME_LIMIT'] = int(os.environ.get('WTF_CSRF_TIME_LIMIT', 3600))
app.config['WTF_CSRF_CHECK_DEFAULT'] = True
app.config['WTF_CSRF_ENABLED'] = True
app.config['PREFERRED_URL_SCHEME'] = 'https'
force_https = os.environ.get('FORCE_HTTPS', '1') == '1'

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
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# 2. 파일 시스템 설정
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['STATIC_FOLDER'] = os.path.join(BASE_DIR, 'static')

IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp'}
VIDEO_EXTENSIONS = {'mp4', 'mov', 'avi', 'mkv', 'webm'}
DEFAULT_EXTENSIONS = IMAGE_EXTENSIONS.union(VIDEO_EXTENSIONS)

configured_extensions = os.environ.get('ALLOWED_UPLOAD_EXTENSIONS')
if configured_extensions:
    app.config['ALLOWED_UPLOAD_EXTENSIONS'] = {
        ext.strip().lower() for ext in configured_extensions.split(',') if ext.strip()
    }
else:
    app.config['ALLOWED_UPLOAD_EXTENSIONS'] = DEFAULT_EXTENSIONS

# --- 권한 및 로깅 설정 ---
OWNER_DETAIL_ROLES = {'admin', 'owner'}

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


class VerificationLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    username = db.Column(db.String(80), nullable=True)
    client_ip = db.Column(db.String(45), nullable=True)
    filename = db.Column(db.String(120), nullable=True)
    token = db.Column(db.String(255), nullable=True)
    matched_owner = db.Column(db.String(80), nullable=True)
    owner_details_disclosed = db.Column(db.Boolean, default=False, nullable=False)
    matched = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

# 4. 헬퍼 함수
PREFIX_SALT_BYTES = 16
PREFIX_LENGTH_BITS = 16
PREFIX_TOTAL_BITS = PREFIX_SALT_BYTES * 8 + PREFIX_LENGTH_BITS
EMBED_DELTA = float(os.environ.get('WATERMARK_DCT_DELTA', 6.0))


def _bitstring_from_bytes(data: bytes) -> list[int]:
    return [int(bit) for bit in ''.join(f'{byte:08b}' for byte in data)]


def _bytes_from_bits(bits: list[int]) -> bytes:
    return bytes(
        int(''.join(str(bit) for bit in bits[i:i + 8]), 2)
        for i in range(0, len(bits), 8)
    )


def _get_block_coordinates(height: int, width: int):
    h_aligned = height - (height % 8)
    w_aligned = width - (width % 8)
    coords = [(y, x) for y in range(0, h_aligned, 8) for x in range(0, w_aligned, 8)]
    return coords, h_aligned, w_aligned


def _embed_bit_in_block(block: np.ndarray, bit: int) -> np.ndarray:
    dct = cv2.dct(block)
    c_a = dct[2, 3]
    c_b = dct[3, 2]
    if bit == 1:
        if c_a <= c_b + EMBED_DELTA:
            c_a = c_b + EMBED_DELTA
    else:
        if c_b <= c_a + EMBED_DELTA:
            c_b = c_a + EMBED_DELTA
    dct[2, 3] = c_a
    dct[3, 2] = c_b
    block_mod = cv2.idct(dct)
    return np.clip(block_mod, 0, 255)


def _extract_bit_from_block(block: np.ndarray) -> int:
    dct = cv2.dct(block)
    return 1 if dct[2, 3] > dct[3, 2] else 0


def _apply_bit_map_to_plane(plane: np.ndarray, coords, bit_map: dict[int, int]) -> np.ndarray:
    if not bit_map:
        return plane
    region = plane.astype(np.float32)
    applied = 0
    for idx, (y, x) in enumerate(coords):
        bit = bit_map.get(idx)
        if bit is None:
            continue
        block = region[y:y + 8, x:x + 8]
        region[y:y + 8, x:x + 8] = _embed_bit_in_block(block, bit)
        applied += 1
    if applied != len(bit_map):
        raise ValueError('워터마크를 삽입하기 위한 공간이 부족합니다.')
    return np.clip(region, 0, 255).astype(np.uint8)


def _build_bit_map(total_blocks: int, payload: bytes, secret: bytes):
    salt = secrets.token_bytes(PREFIX_SALT_BYTES)
    prefix_bits = _bitstring_from_bytes(salt) + [int(bit) for bit in f'{len(payload):016b}']
    data_bits = _bitstring_from_bytes(payload)
    total_bits = len(prefix_bits) + len(data_bits)
    if total_bits > total_blocks:
        raise ValueError('미디어가 핑거프린트를 담기에 충분히 크지 않습니다.')
    bit_map = {idx: bit for idx, bit in enumerate(prefix_bits)}
    available_indices = list(range(len(prefix_bits), total_blocks))
    rng_seed = int.from_bytes(hmac.new(secret, salt, hashlib.sha256).digest()[:8], 'big')
    rng = random.Random(rng_seed)
    rng.shuffle(available_indices)
    data_indices = available_indices[:len(data_bits)]
    for idx, bit in zip(data_indices, data_bits):
        bit_map[idx] = bit
    return bit_map, salt, len(payload)


def _decode_prefix(prefix_bits: list[int]):
    if len(prefix_bits) < PREFIX_TOTAL_BITS:
        return None, None
    salt_bits = prefix_bits[:PREFIX_SALT_BYTES * 8]
    length_bits = prefix_bits[PREFIX_SALT_BYTES * 8:PREFIX_TOTAL_BITS]
    salt_bytes = _bytes_from_bits(salt_bits)
    payload_length = int(''.join(str(bit) for bit in length_bits), 2)
    return salt_bytes, payload_length


def _decode_payload(prefix_bits: list[int], extra_bits: dict[int, int], total_blocks: int, secret: bytes):
    salt_bytes, payload_length = _decode_prefix(prefix_bits)
    if salt_bytes is None or payload_length is None:
        return None
    data_bits_needed = payload_length * 8
    if data_bits_needed == 0:
        return ''
    available_indices = list(range(PREFIX_TOTAL_BITS, total_blocks))
    if len(available_indices) < data_bits_needed:
        return None
    rng_seed = int.from_bytes(hmac.new(secret, salt_bytes, hashlib.sha256).digest()[:8], 'big')
    rng = random.Random(rng_seed)
    rng.shuffle(available_indices)
    data_indices = available_indices[:data_bits_needed]
    bits = []
    for idx in data_indices:
        bit = extra_bits.get(idx)
        if bit is None:
            return None
        bits.append(bit)
    data_bytes = _bytes_from_bits(bits)
    try:
        return data_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return None


def embed_fingerprint_image(image_path: str, payload: str, secret: bytes):
    payload_bytes = payload.encode('utf-8')
    frame = cv2.imread(image_path, cv2.IMREAD_COLOR)
    if frame is None:
        raise ValueError('이미지를 읽을 수 없습니다.')
    coords, h_aligned, w_aligned = _get_block_coordinates(frame.shape[0], frame.shape[1])
    total_blocks = len(coords)
    bit_map, _, _ = _build_bit_map(total_blocks, payload_bytes, secret)
    ycrcb = cv2.cvtColor(frame, cv2.COLOR_BGR2YCrCb)
    y, cr, cb = cv2.split(ycrcb)
    region = y[:h_aligned, :w_aligned]
    region_modified = _apply_bit_map_to_plane(region, coords, bit_map)
    y[:h_aligned, :w_aligned] = region_modified
    processed = cv2.merge([y, cr, cb])
    result = cv2.cvtColor(processed, cv2.COLOR_YCrCb2BGR)
    base, ext = os.path.splitext(image_path)
    output_path = f"{base}_fp{ext}"
    if not cv2.imwrite(output_path, result):
        raise ValueError('워터마크된 이미지를 저장할 수 없습니다.')
    return output_path


def extract_fingerprint_image(image_path: str, secret: bytes):
    frame = cv2.imread(image_path, cv2.IMREAD_COLOR)
    if frame is None:
        return None
    coords, h_aligned, w_aligned = _get_block_coordinates(frame.shape[0], frame.shape[1])
    if not coords:
        return None
    ycrcb = cv2.cvtColor(frame, cv2.COLOR_BGR2YCrCb)
    y = ycrcb[:, :, 0]
    plane = y[:h_aligned, :w_aligned].astype(np.float32)
    prefix_bits = []
    extra_bits = {}
    for idx, (y_off, x_off) in enumerate(coords):
        block = plane[y_off:y_off + 8, x_off:x_off + 8]
        bit = _extract_bit_from_block(block)
        if idx < PREFIX_TOTAL_BITS:
            prefix_bits.append(bit)
        else:
            extra_bits[idx] = bit
    return _decode_payload(prefix_bits, extra_bits, len(coords), secret)


def embed_fingerprint_video(video_path: str, payload: str, secret: bytes):
    payload_bytes = payload.encode('utf-8')
    capture = cv2.VideoCapture(video_path)
    if not capture.isOpened():
        raise ValueError('동영상을 읽을 수 없습니다.')
    frame_block_counts = []
    success, frame = capture.read()
    while success:
        coords, _, _ = _get_block_coordinates(frame.shape[0], frame.shape[1])
        frame_block_counts.append(len(coords))
        success, frame = capture.read()
    capture.release()
    total_blocks = sum(frame_block_counts)
    if total_blocks == 0:
        raise ValueError('동영상 프레임이 너무 작습니다.')
    bit_map, _, _ = _build_bit_map(total_blocks, payload_bytes, secret)
    capture = cv2.VideoCapture(video_path)
    fps = capture.get(cv2.CAP_PROP_FPS) or 30.0
    width = int(capture.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(capture.get(cv2.CAP_PROP_FRAME_HEIGHT))
    ext = Path(video_path).suffix
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    output_path = f"{os.path.splitext(video_path)[0]}_fp{ext}"
    writer = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
    global_index = 0
    applied_indices = set()
    for count in frame_block_counts:
        success, frame = capture.read()
        if not success:
            break
        coords, h_aligned, w_aligned = _get_block_coordinates(frame.shape[0], frame.shape[1])
        ycrcb = cv2.cvtColor(frame, cv2.COLOR_BGR2YCrCb)
        y, cr, cb = cv2.split(ycrcb)
        region = y[:h_aligned, :w_aligned]
        frame_map = {}
        for local_idx in range(len(coords)):
            global_idx = global_index + local_idx
            bit = bit_map.get(global_idx)
            if bit is not None:
                frame_map[local_idx] = bit
                applied_indices.add(global_idx)
        if frame_map:
            region_modified = _apply_bit_map_to_plane(region, coords, frame_map)
            y[:h_aligned, :w_aligned] = region_modified
        merged = cv2.merge([y, cr, cb])
        writer.write(cv2.cvtColor(merged, cv2.COLOR_YCrCb2BGR))
        global_index += len(coords)
    capture.release()
    writer.release()
    if len(applied_indices) != len(bit_map):
        raise ValueError('워터마크를 삽입하기 위한 동영상 길이가 충분하지 않습니다.')
    return output_path


def extract_fingerprint_video(video_path: str, secret: bytes):
    capture = cv2.VideoCapture(video_path)
    if not capture.isOpened():
        return None
    prefix_bits = []
    extra_bits = {}
    global_index = 0
    while True:
        success, frame = capture.read()
        if not success:
            break
        coords, h_aligned, w_aligned = _get_block_coordinates(frame.shape[0], frame.shape[1])
        if not coords:
            continue
        ycrcb = cv2.cvtColor(frame, cv2.COLOR_BGR2YCrCb)
        y = ycrcb[:, :, 0]
        plane = y[:h_aligned, :w_aligned].astype(np.float32)
        for local_idx, (y_off, x_off) in enumerate(coords):
            global_idx = global_index + local_idx
            block = plane[y_off:y_off + 8, x_off:x_off + 8]
            bit = _extract_bit_from_block(block)
            if global_idx < PREFIX_TOTAL_BITS:
                prefix_bits.append(bit)
            else:
                extra_bits[global_idx] = bit
        global_index += len(coords)
    capture.release()
    if global_index == 0:
        return None
    return _decode_payload(prefix_bits, extra_bits, global_index, secret)


def embed_fingerprint_media(media_path: str, payload: str):
    secret = app.config['FINGERPRINT_SECRET'].encode('utf-8')
    ext = Path(media_path).suffix.lower().lstrip('.')
    if ext in IMAGE_EXTENSIONS:
        return embed_fingerprint_image(media_path, payload, secret)
    if ext in VIDEO_EXTENSIONS:
        return embed_fingerprint_video(media_path, payload, secret)
    raise ValueError('지원되지 않는 파일 형식입니다.')


def extract_fingerprint_media(media_path: str):
    secret = app.config['FINGERPRINT_SECRET'].encode('utf-8')
    ext = Path(media_path).suffix.lower().lstrip('.')
    if ext in IMAGE_EXTENSIONS:
        return extract_fingerprint_image(media_path, secret)
    if ext in VIDEO_EXTENSIONS:
        return extract_fingerprint_video(media_path, secret)
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


def get_client_ip():
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    return request.remote_addr


if force_https:
    @app.before_request
    def enforce_https():
        forwarded_proto = request.headers.get('X-Forwarded-Proto', 'http')
        if request.is_secure or forwarded_proto == 'https':
            return None
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

def allowed_file(filename):
    allowed = app.config.get('ALLOWED_UPLOAD_EXTENSIONS', DEFAULT_EXTENSIONS)
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed

@app.context_processor
def inject_media_extensions():
    return {
        'IMAGE_EXTENSIONS': IMAGE_EXTENSIONS,
        'VIDEO_EXTENSIONS': VIDEO_EXTENSIONS,
        'datetime': datetime
    }

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
            try:
                fingerprinted_path = embed_fingerprint_media(original_file_path, token)
            except ValueError as exc:
                flash(str(exc), 'error')
                return redirect(request.url)
            except Exception as exc:
                print(f"Error embedding watermark: {exc}")
                flash('핑거프린트 삽입 중 오류가 발생했습니다.', 'error')
                return redirect(request.url)

            fingerprinted_filename = os.path.basename(fingerprinted_path)
            new_image = Image(filename=fingerprinted_filename,
                              fingerprint_text=token,
                              user_id=session['user_id'])
            db.session.add(new_image)
            db.session.commit()
            return redirect(url_for('upload_success', filename=fingerprinted_filename, original=original_filename))
        else:
            allowed_list = ', '.join(sorted(app.config.get('ALLOWED_UPLOAD_EXTENSIONS', DEFAULT_EXTENSIONS)))
            flash(f'허용된 파일 형식이 아닙니다. ({allowed_list})', 'error')
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
    if 'user_id' not in session:
        flash('소유권 확인을 사용하려면 먼저 로그인하세요.', 'error')
        return redirect(url_for('login'))

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
            try:
                token = extract_fingerprint_media(temp_path)
            except Exception as exc:
                print(f"Error extracting watermark: {exc}")
                token = None
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)

            if not token:
                db.session.add(VerificationLog(
                    user_id=session.get('user_id'),
                    username=session.get('username'),
                    client_ip=get_client_ip(),
                    filename=filename,
                    token=None,
                    matched_owner=None,
                    owner_details_disclosed=False,
                    matched=False
                ))
                db.session.commit()
                flash('숨겨진 데이터가 감지되지 않았습니다.', 'error')
                return redirect(request.url)

            owner, issued_at = resolve_fingerprint_owner(token)
            allow_owner_details = session.get('role') in OWNER_DETAIL_ROLES
            matched = owner is not None

            db.session.add(VerificationLog(
                user_id=session.get('user_id'),
                username=session.get('username'),
                client_ip=get_client_ip(),
                filename=filename,
                token=token,
                matched_owner=owner,
                owner_details_disclosed=bool(allow_owner_details and matched),
                matched=matched
            ))
            db.session.commit()

            verification = {
                'token': token,
                'matched': matched,
                'owner': owner if allow_owner_details and matched else None,
                'issued_at': issued_at if allow_owner_details and issued_at else None,
                'owner_visible': bool(allow_owner_details and matched)
            }
            return render_template('verify.html', result=verification)
        else:
            allowed_list = ', '.join(sorted(app.config.get('ALLOWED_UPLOAD_EXTENSIONS', DEFAULT_EXTENSIONS)))
            flash(f'허용된 파일 형식이 아닙니다. ({allowed_list})', 'error')
            return redirect(request.url)
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
