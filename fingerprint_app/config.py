import os
from pathlib import Path

IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp'}
VIDEO_EXTENSIONS = {'mp4', 'mov', 'avi', 'mkv', 'webm'}
DEFAULT_EXTENSIONS = IMAGE_EXTENSIONS.union(VIDEO_EXTENSIONS)

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_SQLITE_PATH = os.environ.get('DEFAULT_SQLITE_PATH', BASE_DIR / 'database.db')


class BaseConfig:
    IMAGE_EXTENSIONS = set(IMAGE_EXTENSIONS)
    VIDEO_EXTENSIONS = set(VIDEO_EXTENSIONS)
    OWNER_DETAIL_ROLES = {'admin', 'owner'}

    SECRET_KEY = os.environ.get('SECRET_KEY', 'a_very_secret_key_for_local_dev')
    FINGERPRINT_SECRET = os.environ.get('FINGERPRINT_SECRET', 'local_fingerprint_secret')

    DATABASE_URL = os.environ.get('DATABASE_URL')
    if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    if not DATABASE_URL:
        sqlite_path = Path(DEFAULT_SQLITE_PATH)
        sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        DATABASE_URL = f'sqlite:///{sqlite_path}'
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    WTF_CSRF_TIME_LIMIT = int(os.environ.get('WTF_CSRF_TIME_LIMIT', 3600))
    WTF_CSRF_CHECK_DEFAULT = True
    WTF_CSRF_ENABLED = True

    RATELIMIT_STORAGE_URI = os.environ.get('RATELIMIT_STORAGE_URI', 'memory://')

    PREFERRED_URL_SCHEME = 'https'
    FORCE_HTTPS = os.environ.get('FORCE_HTTPS', '1') == '1'
    ENABLE_SECURE_COOKIES = os.environ.get('ENABLE_SECURE_COOKIES', '1') == '1'

    WATERMARK_DCT_DELTA = float(os.environ.get('WATERMARK_DCT_DELTA', 6.0))
    FFMPEG_BIN = os.environ.get('FFMPEG_BIN', 'ffmpeg')

    USE_TASK_QUEUE = os.environ.get('USE_TASK_QUEUE', '0') == '1'
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    TASK_QUEUE_NAME = os.environ.get('TASK_QUEUE_NAME', 'fingerprinting')
    TASK_QUEUE_THRESHOLD_MB = float(os.environ.get('TASK_QUEUE_THRESHOLD_MB', 100))

    _extensions = os.environ.get('ALLOWED_UPLOAD_EXTENSIONS')
    if _extensions:
        ALLOWED_UPLOAD_EXTENSIONS = {ext.strip().lower() for ext in _extensions.split(',') if ext.strip()}
    else:
        ALLOWED_UPLOAD_EXTENSIONS = DEFAULT_EXTENSIONS

    UPLOAD_FOLDER = str(BASE_DIR / 'uploads')
    STATIC_FOLDER = str(BASE_DIR / 'static')


class DevelopmentConfig(BaseConfig):
    DEBUG = True


class ProductionConfig(BaseConfig):
    DEBUG = False
