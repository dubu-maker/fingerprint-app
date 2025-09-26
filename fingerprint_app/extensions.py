from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


db = SQLAlchemy()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=[])


def init_extensions(app):
    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app, storage_uri=app.config.get('RATELIMIT_STORAGE_URI', 'memory://'))
