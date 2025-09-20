from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from itsdangerous import URLSafeTimedSerializer
from PIL import Image

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key_for_local_dev')
# 데이터베이스 URI를 환경 변수에서 가져오도록 수정
DATABASE_URL = os.environ.get('DATABASE_URL')
# 로컬 PostgreSQL 주소와 Render의 주소 형식이 다르므로, 'postgres://'를 'postgresql://'로 바꿔줍니다.
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
# --- 시리얼라이저 초기화 ---
# app.config['SECRET_KEY']를 사용하여 토큰을 생성하고 검증합니다.
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

UPLOAD_FOLDER = 'uploads'
# static 폴더의 경로를 명시적으로 설정해줍니다.
app.config['STATIC_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def embed_fingerprint(image_path, text_to_embed):
    try:
        # ... (이전과 동일한 embed_fingerprint 함수)
    except Exception as e:
        print(f"Error embedding: {e}")
        return None

def extract_fingerprint(image_path):
    try:
        img = Image.open(image_path).convert('RGB')
        pixels = img.load()
        binary_text = ""
        # 8비트 * (텍스트길이 + 1) 만큼만 읽어서 속도 향상
        # 충분히 큰 값으로 설정하거나, 이미지 전체를 읽어도 무방
        limit = (len(session.get('username', '')) + 1) * 8 
        
        for y in range(img.height):
            for x in range(img.width):
                pixel = pixels[x, y]
                for i in range(3):
                    binary_text += str(pixel[i] & 1)
                    if len(binary_text) >= limit * 3: # 충분한 비트를 읽었으면 조기 종료
                        break
                if len(binary_text) >= limit * 3:
                    break
            if len(binary_text) >= limit * 3:
                break
        
        all_bytes = [binary_text[i: i+8] for i in range(0, len(binary_text), 8)]
        decoded_text = ""
        for byte in all_bytes:
            if byte == '11111111': # 종료 신호
                return decoded_text
            decoded_text += chr(int(byte, 2))
        return "종료 신호를 찾을 수 없거나 데이터가 없습니다."
    except Exception as e:
        print(f"Error extracting: {e}")
        return "추출 중 오류 발생"

# --- DB 모델 정의 ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    plan = db.Column(db.String(20), nullable=False, default='basic')
    
    def __repr__(self):
        return f'<User {self.username}>'

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    fingerprint_text = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('images', lazy=True))

    def __repr__(self):
        return f'<Image {self.filename}>'

# --- 헬퍼 함수 ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- 라우트 (Routes) ---
@app.route('/')
def home():
    video_token = None
    if 'plan' in session:
        if session['plan'] == 'premium':
            video_file = 'video_1080p.mp4'
        else:
            video_file = 'video_720p.mp4'
        # 파일 이름 대신, 파일 이름을 암호화한 '토큰'을 생성
        video_token = s.dumps(video_file)

    if session.get('role') == 'admin':
        user_count = User.query.count()
        recent_users = User.query.order_by(User.id.desc()).limit(5).all()
        return render_template('home.html', 
                               user_count=user_count, 
                               recent_users=recent_users)
    
    return render_template('home.html', video_token=video_token)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        username_regex = re.compile(r'^[a-zA-Z0-9_]{4,20}$')
        password_regex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')

        if not username_regex.match(username):
            flash('사용자 이름은 4~20자의 영문, 숫자, 언더바(_)만 사용할 수 있습니다.', 'error')
            return redirect(url_for('register'))
        
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
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            fingerprint_data = session['username']
            
            new_image = Image(filename=filename, 
                              fingerprint_text=fingerprint_data, 
                              user_id=session['user_id'])
            db.session.add(new_image)
            db.session.commit()

            flash(f"'{filename}' 파일이 성공적으로 업로드되었습니다.")
            return redirect(url_for('upload_success', filename=filename))
        else:
            flash('허용된 파일 형식이 아닙니다. (png, jpg, jpeg, gif)', 'error')
            return redirect(request.url)
    return render_template('upload.html')

# --- '내 이미지' 갤러리 라우트 추가 ---
@app.route('/my-images')
def my_images():
    if 'user_id' not in session:
        flash('먼저 로그인하세요.', 'error')
        return redirect(url_for('login'))
    user_images = Image.query.filter_by(user_id=session['user_id']).order_by(Image.timestamp.desc()).all()
    return render_template('my_images.html', images=user_images)

# --- 핑거프린트 검증 라우트 추가 ---
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

@app.route('/my-images')
def my_images():
    if 'user_id' not in session:
        flash('먼저 로그인하세요.', 'error')
        return redirect(url_for('login'))

    user_images = Image.query.filter_by(user_id=session['user_id']).order_by(Image.timestamp.desc()).all()
    return render_template('my_images.html', images=user_images)

@app.route('/serve_video/<token>')
def serve_video(token):
    if 'user_id' not in session:
        return "Access Denied", 403

    try:
        filename = s.loads(token, max_age=30)
    except:
        return "Invalid or expired link.", 403

    if (session.get('plan') == 'premium' and filename == 'video_1080p.mp4') or \
       (session.get('plan') != 'premium' and filename == 'video_720p.mp4'):
        return send_from_directory(os.path.join(app.config['STATIC_FOLDER'], 'videos'), filename)
    else:
        return "Access Denied based on your plan.", 403

if __name__ == '__main__':
    app.run(debug=True)
