from app import app, db

# 애플리케이션 컨텍스트 안에서 데이터베이스 테이블을 생성합니다.
with app.app_context():
    db.create_all()

print("PostgreSQL 데이터베이스에 테이블이 성공적으로 생성되었습니다.")