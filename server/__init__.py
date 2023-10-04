from flask import Flask
from flask_login import LoginManager
from .config import Config
from .database import db
from flask import Blueprint

login_manager = LoginManager()
bp = Blueprint('auth', __name__)

@login_manager.user_loader
def load_user(user_id):
    from server.models.user import User 
    return User.query.get(int(user_id))

def create_app(config_class=Config):
    template_path = '/home/flash1105/development/code/phase-5/python-p5-project-EntomoConnect/templates'
    app = Flask(__name__, template_folder=template_path)
    app.config.from_object(config_class)

    db.init_app(app)
    login_manager.init_app(app)

    
    return app
