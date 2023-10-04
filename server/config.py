import os

class Config:
    SECRET_KEY = os.environ.get('secret_key', 'secret')

    BASE_DIR = os.path.abspath(os.path.dirname(__file__))


    DB_DIRECTORY =os.path.join(BASE_DIR, 'data')
    if not os.path.exists(DB_DIRECTORY):
        os.makedirs(DB_DIRECTORY)

    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(DB_DIRECTORY, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False