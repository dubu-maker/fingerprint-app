import os
from datetime import datetime
from pathlib import Path

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from ..extensions import db, limiter
from ..models import User, Image, VerificationLog
from ..services import watermark

main_bp = Blueprint('main', __name__)


def allowed_file(filename: str) -> bool:
    allowed = current_app.config['ALLOWED_UPLOAD_EXTENSIONS']
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed


def get_client_ip() -> str:
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    return request.remote_addr


@main_bp.context_processor
def inject_globals():
    return {
        'IMAGE_EXTENSIONS': current_app.config['IMAGE_EXTENSIONS'],
        'VIDEO_EXTENSIONS': current_app.config['VIDEO_EXTENSIONS'],
        'datetime': datetime
    }


@main_bp.route('/')
def home():
    video_token = None
    if session.get('user_id') and session.get('role') != 'admin':
        serializer = current_app.extensions['video_token_serializer']
        video_token = serializer.dumps('print.mp4')

    if session.get('role') == 'admin':
        user_count = User.query.count()
        recent_users = User.query.order_by(User.id.desc()).limit(5).all()
        return render_template('home.html', user_count=user_count, recent_users=recent_users, video_token=video_token)

    return render_template('home.html', video_token=video_token)


@main_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not current_app.config['USERNAME_REGEX'].match(username):
            flash('사용자 이름은 4~20자의 영문, 숫자, 언더바(_)만 사용할 수 있습니다.', 'error')
            return redirect(url_for('main.register'))

        if not current_app.config['PASSWORD_REGEX'].match(password):
            flash('비밀번호는 최소 8자 이상이며, 대/소문자, 숫자, 특수문자(@$!%*?&)를 각각 하나 이상 포함해야 합니다.', 'error')
            return redirect(url_for('main.register'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('이미 존재하는 사용자 이름입니다.', 'error')
            return redirect(url_for('main.register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        role = 'admin' if User.query.count() == 0 else 'user'
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash(f"'{username}' 계정 가입 성공! 이제 로그인하세요.")
        return redirect(url_for('main.login'))

    return render_template('register.html')


@main_bp.route('/login', methods=['GET', 'POST'])
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
            return redirect(url_for('main.home'))
        else:
            flash('사용자 이름이 없거나 비밀번호가 틀렸습니다.', 'error')
    return render_template('login.html')


@main_bp.route('/logout')
def logout():
    session.clear()
    flash('성공적으로 로그아웃되었습니다.')
    return redirect(url_for('main.home'))


@main_bp.route('/users')
def show_users():
    if session.get('role') == 'admin':
        all_users = User.query.all()
        return render_template('users.html', users=all_users)
    flash('접근 권한이 없습니다.', 'error')
    return redirect(url_for('main.login'))


@main_bp.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if session.get('role') != 'admin':
        flash('삭제 권한이 없습니다.', 'error')
        return redirect(url_for('main.home'))
    user_to_delete = User.query.get_or_404(user_id)
    db.session.delete(user_to_delete)
    db.session.commit()
    flash(f'사용자 ID {user_id}가 성공적으로 삭제되었습니다.')
    return redirect(url_for('main.show_users'))


@main_bp.route('/update_plan/<int:user_id>', methods=['POST'])
def update_plan(user_id):
    if session.get('role') != 'admin':
        flash('권한이 없습니다.', 'error')
        return redirect(url_for('main.home'))
    new_plan = request.form.get('plan')
    if new_plan not in ['basic', 'premium']:
        flash('잘못된 등급입니다.', 'error')
        return redirect(url_for('main.show_users'))
    user_to_update = User.query.get_or_404(user_id)
    user_to_update.plan = new_plan
    db.session.commit()
    flash(f'{user_to_update.username} 사용자의 등급이 {new_plan}(으)로 변경되었습니다.')
    return redirect(url_for('main.show_users'))


@main_bp.route('/upload', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=['POST'], per_method=True, error_message='업로드 요청은 분당 5회로 제한됩니다.')
def upload_file():
    if 'username' not in session:
        flash('이미지를 업로드하려면 먼저 로그인하세요.', 'error')
        return redirect(url_for('main.login'))
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
            upload_folder = current_app.config['UPLOAD_FOLDER']
            original_file_path = os.path.join(upload_folder, original_filename)
            file.save(original_file_path)

            token = watermark.generate_token(session['username'])
            ext = original_filename.rsplit('.', 1)[-1].lower()
            file_size_mb = os.path.getsize(original_file_path) / (1024 * 1024)
            threshold = current_app.config['TASK_QUEUE_THRESHOLD_MB']
            rq_queue = current_app.extensions.get('rq_queue')
            use_queue = rq_queue is not None and (ext in current_app.config['VIDEO_EXTENSIONS'] or file_size_mb >= threshold)

            if use_queue:
                job = rq_queue.enqueue('fingerprint_app.services.watermark.process_watermark_job',
                                       args=(session['user_id'], session['username'], original_filename, original_file_path, token),
                                       result_ttl=3600,
                                       failure_ttl=3600)
                flash('워터마크 작업이 백그라운드에서 실행 중입니다. 처리 상태 페이지로 이동합니다.')
                return redirect(url_for('main.processing_status', job_id=job.get_id(), original=original_filename))

            try:
                fingerprinted_path = watermark.embed_media(original_file_path, token)
            except ValueError as exc:
                flash(str(exc), 'error')
                return redirect(request.url)
            except Exception as exc:
                current_app.logger.exception("Error embedding watermark: %s", exc)
                flash('핑거프린트 삽입 중 오류가 발생했습니다.', 'error')
                return redirect(request.url)

            fingerprinted_filename = os.path.basename(fingerprinted_path)
            new_image = Image(filename=fingerprinted_filename,
                              fingerprint_text=token,
                              user_id=session['user_id'])
            db.session.add(new_image)
            db.session.commit()
            return redirect(url_for('main.upload_success', filename=fingerprinted_filename, original=original_filename))
        else:
            allowed_list = ', '.join(sorted(current_app.config['ALLOWED_UPLOAD_EXTENSIONS']))
            flash(f'허용된 파일 형식이 아닙니다. ({allowed_list})', 'error')
            return redirect(request.url)
    return render_template('upload.html')


@main_bp.route('/my-images')
def my_images():
    if 'user_id' not in session:
        flash('먼저 로그인하세요.', 'error')
        return redirect(url_for('main.login'))
    user = User.query.get(session['user_id'])
    return render_template('my_images.html', images=user.images)


@main_bp.route('/delete-media/<int:image_id>', methods=['POST'])
def delete_media(image_id):
    if 'user_id' not in session:
        flash('먼저 로그인하세요.', 'error')
        return redirect(url_for('main.login'))

    media = Image.query.get_or_404(image_id)
    if media.user_id != session['user_id']:
        flash('삭제 권한이 없습니다.', 'error')
        return redirect(url_for('main.my_images'))

    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], media.filename)
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
    except OSError as exc:
        current_app.logger.warning("파일 삭제 실패: %s", exc)

    db.session.delete(media)
    db.session.commit()
    flash(f"'{media.filename}' 파일을 삭제했습니다.")
    return redirect(url_for('main.my_images'))


@main_bp.route('/verify', methods=['GET', 'POST'])
@limiter.limit("10 per minute", methods=['POST'], per_method=True, error_message='검증 요청은 분당 10회로 제한됩니다.')
def verify_fingerprint():
    if 'user_id' not in session:
        flash('소유권 확인을 사용하려면 먼저 로그인하세요.', 'error')
        return redirect(url_for('main.login'))

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
            temp_path = os.path.join(current_app.config['UPLOAD_FOLDER'], f"temp_{filename}")
            file.save(temp_path)
            try:
                token = watermark.extract_media(temp_path)
            except Exception as exc:
                current_app.logger.exception("Error extracting watermark: %s", exc)
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

            owner, issued_at = watermark.resolve_owner(token)
            allow_details = session.get('role') in current_app.config['OWNER_DETAIL_ROLES']
            matched = owner is not None

            db.session.add(VerificationLog(
                user_id=session.get('user_id'),
                username=session.get('username'),
                client_ip=get_client_ip(),
                filename=filename,
                token=token,
                matched_owner=owner,
                owner_details_disclosed=bool(allow_details and matched),
                matched=matched
            ))
            db.session.commit()

            verification = {
                'token': token,
                'matched': matched,
                'owner': owner if allow_details and matched else None,
                'issued_at': issued_at if allow_details and issued_at else None,
                'owner_visible': bool(allow_details and matched)
            }
            return render_template('verify.html', result=verification)
        else:
            allowed_list = ', '.join(sorted(current_app.config['ALLOWED_UPLOAD_EXTENSIONS']))
            flash(f'허용된 파일 형식이 아닙니다. ({allowed_list})', 'error')
            return redirect(request.url)
    return render_template('verify.html', result=None)


@main_bp.route('/processing/<job_id>')
def processing_status(job_id):
    rq_queue = current_app.extensions.get('rq_queue')
    if not rq_queue:
        flash('작업 대기열이 활성화되어 있지 않습니다.', 'error')
        return redirect(url_for('main.upload_file'))

    try:
        job = rq_queue.fetch_job(job_id)
    except Exception as exc:
        current_app.logger.error("Error fetching job %s: %s", job_id, exc)
        job = None

    if job is None:
        flash('지정된 작업을 찾을 수 없습니다.', 'error')
        return redirect(url_for('main.upload_file'))

    if job.is_failed:
        flash('워터마크 처리 중 오류가 발생했습니다.', 'error')
        return redirect(url_for('main.upload_file'))

    if job.is_finished:
        fingerprinted_filename = job.result
        if not fingerprinted_filename:
            flash('처리 결과를 확인할 수 없습니다.', 'error')
            return redirect(url_for('main.upload_file'))
        original = request.args.get('original')
        return redirect(url_for('main.upload_success', filename=fingerprinted_filename, original=original))

    return render_template('processing.html', job_id=job_id, original=request.args.get('original'))


@main_bp.route('/success/<filename>')
def upload_success(filename):
    original = request.args.get('original')
    return render_template('result.html', filename=filename, original_filename=original)


@main_bp.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename)


@main_bp.route('/serve_video/<token>')
def serve_video(token):
    if 'user_id' not in session:
        return "Access Denied", 403
    serializer = current_app.extensions['video_token_serializer']
    try:
        filename = serializer.loads(token, max_age=30)
    except Exception:
        return "Invalid or expired link.", 403

    if filename != 'print.mp4':
        return "Access Denied", 403

    return send_from_directory(Path(current_app.config['STATIC_FOLDER']) / 'videos', filename)
