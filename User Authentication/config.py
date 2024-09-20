from datetime import timedelta

class Config:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///db.sqlite3'

    JWT_SECRET_KEY = 'jwt_secret_key'
    JWT_TOKEN_LOCATION = ['headers']
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)

    SECRET_KEY = 'your_secret_key'
