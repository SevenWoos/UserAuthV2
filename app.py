from flask import Flask, render_template, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
# To hash our passwords
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Used to reload User object from user id stored in session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Database Tables
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20
    )], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20
    )], render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    # Check for duplicate usernames
    def validate_username(self, username):
        # Query database for the username
        existing_username = User.query.filter_by(
            username=username.data).first()
        if existing_username:
            raise ValidationError(
                "That username already exists. Please choose a different one!"
            )
        
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20
    )], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20
    )], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")



@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
# Only access dashboard if we're logged in
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        # Hash password so it is not stored as plain text
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        # Add new user to DB and commit changes
        db.session.add(new_user)
        db.session.commit()

        # Redirect to login
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("You do not have permission to access this page!", "danger")
        return redirect(url_for('home'))
    return render_template('admin_dashboard.html', user=current_user)


# --- Register Blueprints LAST to avoid circular imports ---
from routes import chat_bp
app.register_blueprint(chat_bp)


if __name__ == '__main__':
    app.run(debug=True)

