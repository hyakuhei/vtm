from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import  SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, passwordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError

#initialize the app
app = Flask(__name__)
app.config['SECRET_KEY'] = "secret-key-not-for-github"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vtm-database.db'

db = SQLAlchemy(app)

#Initialize Flask Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# User model
class User(UserMixin, db.Model):
        id = id.Column(db.Integer, primary_key=True)
        username = db.Column(db.string(150), nullable=False, unique=True)
        password = db.Column(db.string(150), nullable=False)

# Flask-login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
