from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_babel import Babel


db = SQLAlchemy()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=[])
babel = Babel()


def init_extensions(app):
    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
