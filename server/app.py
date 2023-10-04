from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user
from werkzeug.security import check_password_hash, generate_password_hash
from enum import Enum
from flask_sqlalchemy import SQLAlchemy
from auth.forms import LoginForm, RegisterForm
from flask_session import Session

import os
app = Flask(__name__, template_folder=os.path.join(os.getcwd(), 'templates'))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SECRET_KEY'] = 'not-so-secret'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] =  True


db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
Session(app)


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
    


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            flash('You were successfully logged in!', 'success')
            return redirect(url_for('auth.dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('You were successfully logged out!', 'success')
    return redirect(url_for('main.index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')   
        return redirect(url_for('auth.login'))
    return render_template('register.html', form=form)

@app.route('/dashboard')
@login_required 
def dashboard():
    observations = Observation.query.all()
    discussions = Discussion.query.all()
    return render_template('dashboard.html', observations=observations, discussions=discussions)


# display list of observations
@app.route('/observations')
def observations():
    obs_list = Observation.query.all()
    return render_template('observations.html', observations=obs_list)

@app.route('/observation/<int:obs_id>', methods=['GET', 'POST'])
def observation_detail(obs_id):
    observation = Observation.query.get(obs_id)
    if request.method == 'POST':
        message = request.form.get('message')
        if message: 
            discussion = Discussion(message=message, user_id=session['user_id'], observation_id=obs_id)
            db.session.add(discussion)
            db.session.commit()
            flash ('Discussion added successfully!', 'success')
            return redirect(url_for('observation.observation_details', obs_id=obs_id))

    discussions = Discussion.query.filter_by(observation_id=obs_id).all()
    return render_template('observation_detail.html', observation=observation, discussions=discussions)

@app.route('/observations/new', methods=['GET', 'POST'])
def new_observation():
    if request.method =='POST':
        species = request.form['species']
        location = request.form['location']
        behavior = request.form['behavior']
        user_id = session['user_id']
        images = request.form['images']
        new_observation = Observation(species=species, location=location, behavior=behavior, user_id=user_id, images=images)
        db.session.add(new_observation)
        db.session.commit()
        return redirect(url_for('observation.observations'))
    return render_template('new_observation.html')

if __name__ == '__main__':
    app.run(debug=True)
    