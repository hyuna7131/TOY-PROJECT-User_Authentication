from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager

db = SQLAlchemy()
jwt = JWTManager()

def create_app():
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///localhost:8000'
    app.config['JWT_SECRET_KEY'] = 'jwt_secret_key'

    db.init_app(app)
    jwt.init_app(app)
    
    from app.routes import main
    app.register_blueprint(main)

    return app