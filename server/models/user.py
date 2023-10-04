from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from server.database import db
from enum import Enum
from flask_login import UserMixin


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
    
    is_active = db.Column(db.Boolean, default=True)
    pass
    
    @property
    def is_active(self):
        return True
        
    # Hashing the password before saving
    def set_password(self, password: str) -> None:
        """Generate a hashed password."""
        self.password_hash = generate_password_hash(password)
    
    # Verifying the password
    def check_password(self, password: str) -> bool:
        """Verify if the password hash matches the actual password."""
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self) -> str:
        """Provide a readable representation of the User object."""
        return f"<User {self.username}>"