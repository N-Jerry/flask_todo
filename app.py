from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import secrets

from flask import render_template, url_for, flash, redirect, request, session
# from app import app, db
#from forms import RegistrationForm, LoginForm, EditTaskForm
# from models import User, Task
# from flask_login import login_user, current_user, logout_user, login_required, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError

from flask_session import Session

# Configure application
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
db = SQLAlchemy(app)


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# login_manager = LoginManager(app)
# login_manager.login_view = 'login'
# login_manager.login_message_category = 'info'



#models.py
# @login_manager.user_loader
# def load_user(user_id):
#     return User.query.get(int(user_id))


#Didn't use emails because the project scope isn't that demanding

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    #email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    tasks = db.relationship('Task', backref='author', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)




#forms.py
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)], name="username")
    #email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()], name="password")
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')], name="confirm_password")
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    # def validate_email(self, email):
    #     user = User.query.filter_by(email=email.data).first()
    #     if user:
    #         raise ValidationError('That email is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    #email = StringField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired()], name="username")
    password = PasswordField('Password', validators=[DataRequired()], name="password")
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class NewTaskForm(FlaskForm):
    content = StringField('Task Content', validators=[DataRequired()], name="content")
    submit = SubmitField('Create Task')

class EditTaskForm(FlaskForm):
    content = StringField('Task Content', validators=[DataRequired()], name="content")
    submit = SubmitField('Update Task')

#routes.py
@app.route("/tasks", methods=["GET", "POST"])
def tasks():

    form = NewTaskForm()
    user = session["user"]
    if user:
        if request.method == "POST":
            task_content = form.content.data
            new_task = Task(content=task_content, user_id=user.id)
            try:
                db.session.add(new_task)
                db.session.commit()
                return redirect(url_for('tasks'))
            except Exception as e:
                print(f"ERROR: {e}")
        else:
            tasks = Task.query.filter_by(user_id=user.id).order_by(Task.created_at).all()
            return render_template('index.html', tasks=tasks, form=form, user=user) 
    return redirect(url_for('login'))

@app.route("/delete/<int:task_id>/<int:user_id>")
def delete(task_id: int, user_id: int):
    
    if session["user"].id == user_id:
        task = Task.query.get_or_404(task_id)
        try:
            db.session.delete(task)
            db.session.commit()
            flash('Your task has been deleted!','message')
            return redirect(url_for('tasks'))
            flash('Your task has been deleted!','message')
        except Exception as e:
            print(f"ERROR: {e}")
    
    return redirect(url_for('login'))


@app.route("/")
def home():
    return render_template('home.html')


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if request.method == "POST":
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    session.clear()
    form = LoginForm()
    if request.method == "POST":
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session["user"] = user
            flash('Login Successful.', 'success')
            return redirect(url_for('tasks'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect(url_for('home'))
    


@app.route("/edit/<int:task_id>/<int:user_id>", methods=['GET', 'POST'])
def edit(task_id: int, user_id: int):
    task = Task.query.get_or_404(task_id)
    form = EditTaskForm()
    if session["user"].id == user_id:
        if request.method == "POST":
            task.content = form.content.data
            db.session.commit()
            flash('Your task has been updated!', 'success')
            return redirect(url_for('tasks'))
        elif request.method == 'GET':
            form.content.data = task.content
        return render_template('edit.html', title='Edit Task', form=form, task=task, user_id=user_id)
    return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)