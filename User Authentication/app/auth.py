from flask_jwt_extended import get_jwt_identity
from app.models import User

def is_login(token, firstname, logged_in):
    if token:
        try:
            identity = get_jwt_identity()  # 사용자 ID를 가져옵니다.
            user = User.query.get(identity)  # 사용자 정보를 데이터베이스에서 조회합니다.
            if user:
                logged_in = True
                firstname = user.firstname  # 사용자 이름을 가져옵니다.
        except Exception:
            logged_in = False
    return 