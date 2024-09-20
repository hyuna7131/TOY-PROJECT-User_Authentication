from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from config import Config

db = SQLAlchemy()
jwt = JWTManager()
bcrypt = Bcrypt()

def create_app():
    app = Flask(__name__)
    # 환경변수 세팅
    app.config.from_object(Config)

    db.init_app(app) 
    jwt.init_app(app)
    bcrypt.init_app(app)

    from app.models import User

    @jwt.user_lookup_loader
    def load_user_callback(_jwt_header, jwt_data):
        identity = jwt_data["sub"]
        return User.query.get(int(identity))
    
    from app.routes import main
    app.register_blueprint(main)

    return app