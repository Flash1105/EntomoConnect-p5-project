from flask import Flask, render_template
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from enum import Enum
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SECRET_KEY'] = 'not-so-secret'
db = SQLAlchemy(app)

class UserRole(Enum):
    ENTHUSIAST = 'enthusiast'
    ENTOMOLOGIST = 'entomologist'

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.Enum(UserRole), default=UserRole.ENTHUSIAST)

    @property 
    def is_active(self):
        return True
    
    def set_password(self, password: str) -> None:
        """Generate a hashed password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify if the password hash matches the actual password."""
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self) -> str:
        """Provide a readable representation of the User object."""
        return f"<User {self.username}>"
    
class Observation(db.Model):
    __tablename__ = 'observations'
    id = db.Column(db.Integer, primary_key=True)
    species = db.Column(db.String, nullable=False)
    location = db.Column(db.String, nullable=False)
    behavior = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    images = db.Column(db.String, nullable=False)

    discussions = db.relationship('Discussion', back_populates='observation', lazy=True)

class Discussion(db.Model):
    __tablename__ = 'discussions'

    discussion_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    observation_id = db.Column(db.Integer, db.ForeignKey('observations.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)

    observation = db.relationship('Observation', back_populates='discussions')

    @app.route('/')
    def index():
        return render_template('index.html')
    
if __name__ == '__main__':
    app.run(debug=True)
    