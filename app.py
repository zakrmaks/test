from flask_mail import Mail
from flask import Flask, render_template, request, redirect, flash, url_for
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_required, login_user, current_user, logout_user
from wtforms import StringField, SubmitField, TextAreaField,  BooleanField, PasswordField
from wtforms.validators import DataRequired

app = Flask(__name__)

app.config.from_pyfile('config.cfg')
db = SQLAlchemy(app)
migrate = Migrate(app,  db)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'You can\'t access that page. You need to login first.'


@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(100))
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(100), nullable=False)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)
    updated_on = db.Column(db.DateTime(), default=datetime.utcnow,  onupdate=datetime.utcnow)

    def __repr__(self):
	    return "<{}:{}>".format(self.id, self.username)


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)





class LoginForm():
   def validate_on_submit(self):
    self.username = StringField("Username", validators=[DataRequired()])
    self.password = PasswordField("Password", validators=[DataRequired()])
    self.remember = BooleanField("Remember Me")
    self.submit = SubmitField()

@app.route('/')
def hello_world():
    return 'Hello World!'



@app.route('/admin/')
@login_required
def admin():
   return render_template('admin.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        user = User.query.filter_by(username=username).first()

        if not user:
            return '<h1>User does not exist!</h1>'

        login_user(user)

        return '<h1>You are now logged in!</h1>'

    return render_template('login.html')


@app.route('/home')
@login_required
def home():
    return '<h1>You are in the protected area, {}!</h1>'.format(current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return '<h1>You are now logged out!</h1>'

if __name__ == '__main__':
    app.run()