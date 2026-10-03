from flask import Flask, render_template, redirect, url_for, flash, request
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from forms import RegistrationForm, LoginForm

app = Flask(__name__)

app.config['SECRET_KEY'] = 'clave_super_secreta'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['REMEMBER_COOKIE_HTTPONLY'] = True

csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

users_db = {}

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

@login_manager.user_loader
def load_user(user_id):
    if user_id in users_db:
        u = users_db[user_id]
        return User(u['id'], u['username'], u['password_hash'])
    return None

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user_id = str(len(users_db) + 1)
        hashed_password = generate_password_hash(form.password.data)
        users_db[user_id] = {
            'id': user_id,
            'username': form.username.data,
            'password_hash': hashed_password
        }
        flash('Registro exitoso. Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form, modal_form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    modal_form = RegistrationForm()
    if form.validate_on_submit():
        user_data = None
        for u in users_db.values():
            if u['username'] == form.username.data:
                user_data = u
                break
        if user_data and check_password_hash(user_data['password_hash'], form.password.data):
            user_obj = User(user_data['id'], user_data['username'], user_data['password_hash'])
            login_user(user_obj)
            flash('Inicio de sesión exitoso', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Credenciales inválidas', 'danger')
    return render_template('login.html', form=form, modal_form=modal_form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión', 'info')
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    modal_form = RegistrationForm()
    return render_template('profile.html', user=current_user, modal_form=modal_form)

@app.errorhandler(401)
def unauthorized(e):
    return render_template('401.html'), 401

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

if __name__ == '__main__':
    app.run(debug=True)