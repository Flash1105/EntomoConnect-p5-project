from flask_sqlalchemy import SQLAlchemy
from server.database import db

class Observation(db.Model):
    __tablename__ = 'observations'
    id = db.Column(db.Integer, primary_key=True)
    species = db.Column(db.String, nullable=False)
    location = db.Column(db.String, nullable=False)
    behavior = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    images = db.Column(db.String, nullable=False)

    discussions = db.relationship('Discussion', back_populates='observation', lazy=True)
