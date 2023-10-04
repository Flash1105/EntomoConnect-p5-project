from flask import Flask
from flask_login import LoginManager
from .config import Config
from .database import db


login_manager = LoginManager()


@login_manager.user_loader
def load_user(user_id):
    from server.models.user import User 
    return User.query.get(int(user_id))


import sys
import os

def create_app(config_class=Config):
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

    sys.path.insert (0, project_root)
    template_path = '/home/flash1105/development/code/phase-5/python-p5-project-EntomoConnect/templates'
    app = Flask(__name__, template_folder=template_path)
    app.config.from_object(config_class)

    from auth.routes import auth, observation_bp
    
    app.register_blueprint(auth, url_prefix='/auth')
    app.register_blueprint(observation_bp, url_prefix='/observation')

    db.init_app(app)
    login_manager.init_app(app)

    
    return app
