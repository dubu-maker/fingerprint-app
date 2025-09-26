from fingerprint_app import create_app
from fingerprint_app.extensions import db


def main():
    """Create all database tables using the application factory."""
    app = create_app()
    with app.app_context():
        db.create_all()
    print("데이터베이스 테이블이 성공적으로 생성되었습니다.")


if __name__ == '__main__':
    main()
