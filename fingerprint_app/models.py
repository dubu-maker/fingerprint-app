from datetime import datetime

from .extensions import db


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
    fingerprint_text = db.Column(db.String(255), nullable=False)
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
