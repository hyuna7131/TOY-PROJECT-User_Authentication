from app import db
from flask_jwt_extended import JWTManager
from datetime import datetime

class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.String(20), primary_key=True)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    school = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(100), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')

    def __repr__(self):
        return f"User('{self.firstname}', '{self.email}', '{self.image_file}')"

class Post(db.Model):
    __tablename__ = "post"

    id = db.Column(db.String(20), primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime)
    content = db.Column(db.Text, nullable=False)
    secret = db.Column(db.Boolean, nullable=False, default=False)
    secret_password = db.Column(db.String(60), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"