import os
import re
from pathlib import Path

from flask import Flask, redirect, request, url_for, flash, session
from flask_babel import gettext as _
from itsdangerous import URLSafeTimedSerializer
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_limiter.errors import RateLimitExceeded
from flask_wtf.csrf import CSRFError

from .config import BaseConfig, IMAGE_EXTENSIONS, VIDEO_EXTENSIONS
from .extensions import init_extensions, babel
from .routes.main import main_bp


USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_]{4,20}$')
PASSWORD_REGEX = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')


def create_app(config_class=BaseConfig):
    app = Flask(
        __name__,
        static_folder=config_class.STATIC_FOLDER,
        template_folder=config_class.TEMPLATE_FOLDER
    )
    app.config.from_object(config_class)

    Path(app.config['UPLOAD_FOLDER']).mkdir(parents=True, exist_ok=True)

    init_extensions(app)

    from . import models  # noqa: F401

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    app.extensions['video_token_serializer'] = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    app.config['IMAGE_EXTENSIONS'] = IMAGE_EXTENSIONS
    app.config['VIDEO_EXTENSIONS'] = VIDEO_EXTENSIONS
    app.config['USERNAME_REGEX'] = USERNAME_REGEX
    app.config['PASSWORD_REGEX'] = PASSWORD_REGEX

    if app.config.get('ENABLE_SECURE_COOKIES'):
        app.config.update(
            SESSION_COOKIE_SECURE=True,
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE=os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax'),
            REMEMBER_COOKIE_SECURE=True,
            REMEMBER_COOKIE_HTTPONLY=True,
            REMEMBER_COOKIE_SAMESITE=os.environ.get('REMEMBER_COOKIE_SAMESITE', 'Lax')
        )

    from redis import Redis
    from rq import Queue

    rq_queue = None
    if app.config['USE_TASK_QUEUE']:
        try:
            redis_conn = Redis.from_url(app.config['REDIS_URL'])
            rq_queue = Queue(app.config['TASK_QUEUE_NAME'], connection=redis_conn)
        except Exception as exc:
            app.logger.warning("Redis 큐에 연결할 수 없습니다: %s", exc)
            rq_queue = None
    app.extensions['rq_queue'] = rq_queue

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        flash(_('보안 검증이 만료되었거나 잘못되었습니다. 페이지를 새로고침한 뒤 다시 시도해 주세요.'), 'error')
        return redirect(request.referrer or url_for('main.home')), 400

    @app.errorhandler(RateLimitExceeded)
    def handle_rate_limit(error):
        flash(_('요청이 너무 자주 발생했습니다. 잠시 후 다시 시도해 주세요.'), 'error')
        target = request.referrer or url_for('main.home')
        return redirect(target), 429

    def select_locale():
        requested = session.get('locale')
        if requested in app.config['LANGUAGES']:
            return requested
        return request.accept_languages.best_match(app.config['LANGUAGES']) or app.config['BABEL_DEFAULT_LOCALE']

    babel.init_app(app, locale_selector=select_locale)

    if app.config['FORCE_HTTPS']:
        @app.before_request
        def enforce_https():
            if request.is_secure:
                return None
            if request.headers.get('X-Forwarded-Proto', 'http') == 'https':
                return None
            return redirect(request.url.replace('http://', 'https://', 1), code=301)

    app.register_blueprint(main_bp)

    return app
