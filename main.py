from datetime import datetime, timedelta
from flask import Flask, abort, render_template, redirect, url_for, flash, session
from flask_bootstrap import Bootstrap5
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, or_
import time
from sqlalchemy.exc import IntegrityError
from flask_mail import Mail,Message
import secrets
import string
import random

from forms import *



app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
Bootstrap5(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# mailtrap config
app.config['MAIL_SERVER'] = 'smtp.office365.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'magazynek18@outlook.com'
app.config['MAIL_PASSWORD'] = 'Testowanie18'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)



@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy()
db.init_app(app)




class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(20),unique =True,nullable=False)
    password = db.Column(db.String(100),nullable=False)
    name= db.Column(db.String(30),nullable=False)
    last_name= db.Column(db.String(30),nullable=False)
    city = db.Column(db.String(30),nullable=False)
    postal_code = db.Column(db.String(6),nullable=False)
    street = db.Column(db.String(20),nullable=False)
    street_number = db.Column(db.String,nullable=False)
    flat_number = db.Column(db.String)                 
    pesel = db.Column(db.String(30), unique = True,nullable=False)
    birth_date = db.Column(db.Date,nullable=False)
    sex = db.Column(db.String(15))
    email = db.Column(db.String(100), unique=True,nullable=False)
    phone = db.Column(db.Integer)
    pass_ch_req=db.Column(db.String)
    password_history=db.Column(db.String)

with app.app_context():
    db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))

        if current_user.id != 1:
            return abort(403)

        return f(*args, **kwargs)

    return decorated_function


# Główna strona
@app.route('/', methods=['GET', 'POST'])
def mainpage():
    form = ChangePasswordForm()
    show_password_change = is_password_required()

    if form.validate_on_submit() and is_password_required():
        user = current_user
        password = form.new_password.data
        isUsed=is_used(user, password)
        if isUsed:
            flash('Hasło bylo uzyte','modal')
            return render_template("index.html", show_password_change=show_password_change, form=form)


        if not isUsed:
            set_password(user, password)
            current_user.pass_ch_req = 0
            db.session.commit()
            return render_template("index.html", show_password_change=show_password_change, form=form)

    else:
        show_password_change = is_password_required()
        return render_template("index.html", show_password_change=show_password_change, form=form)


@app.route('/edit-profile', methods=['GET', 'POST'])
def edit_profile():

    form = AddUserForm()

    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.get(current_user.id)


        result = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()
        if result and result.id != current_user.id:
            flash("Taki e-mail już istnieje!")
            return render_template('edit-profile.html', form=form, user=user)

        result = db.session.execute(db.select(User).where(User.pesel == form.pesel.data)).scalar()
        if result and result.id != current_user.id:
            flash("Taki pesel już istnieje!")
            return render_template('edit-profile.html', form=form, user=user)


        user.name = form.name.data
        user.email = form.email.data
        user.password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        
        db.session.commit()


    return render_template('edit-profile.html', form=form, current_user=current_user)


@app.route('/adduser', methods=['GET', 'POST'])
@admin_only
def add_user():
    try:

        form = AddUserForm()


        existing_errors = []

        existing_email = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()
        if existing_email:
            existing_errors.append("Ten adres e-mail jest już zarejestrowany.")

        existing_login = db.session.execute(db.select(User).where(User.login == form.login.data)).scalar()
        if existing_login:
            existing_errors.append("Ten login jest już zajęty.")

        existing_pesel = db.session.execute(db.select(User).where(User.pesel == form.pesel.data)).scalar()
        if existing_pesel:
            existing_errors.append("Ten numer PESEL już istnieje w bazie danych.")

        if existing_errors:
            for error in existing_errors:
                flash(error, 'error')
            return render_template('add_user.html', form=form)
        
        if form.validate_on_submit():
                hash_and_salted_password = generate_password_hash(
                    form.password.data,
                    method='pbkdf2:sha256',
                    salt_length=8
                )

                new_user = User(
                    login=form.login.data, 
                    password=hash_and_salted_password,
                    name=form.name.data,
                    last_name=form.last_name.data,
                    city=form.city.data,
                    postal_code=form.postal_code.data,
                    street=form.street.data,
                    street_number=form.street_number.data,
                    flat_number=form.flat_number.data,
                    pesel=form.pesel.data,
                    birth_date=form.birth_date.data,
                    email=form.email.data,
                    sex=form.sex.data,
                    phone=form.phone.data,
                )

                db.session.add(new_user)
                db.session.commit()

                return redirect(url_for('user_profile', user_id=new_user.id))

        return render_template('add_user.html', form=form)
    except IntegrityError:
        flash('integrite o    ', 'error')

        return render_template('add_user.html', form=form)


@app.route('/users_and_search', methods=['GET', 'POST'])
@admin_only
def user_search():
    search_form = SearchForm()
    users = []
    query = request.args.get('query', '').lower()
    category = request.args.get('search_category', '')

    if category and query:
        if category.isdigit():
            category = int(category)

            if category == 1:  # Login
                users = User.query.filter(User.login.ilike(f'%{query}%')).all() 
            elif category == 2:  # E-mail
                users = User.query.filter(User.email.ilike(f'%{query}%')).all() 
            elif category == 3:  # Imię i nazwisko

                queries = query.split()
                if len(queries) == 2:
                    first_name, last_name = queries
                    users = User.query.filter(User.name.ilike(f'%{first_name}%'), User.last_name.ilike(f'%{last_name}%')).all()
                elif len(queries) == 1:
                    search_query = queries[0]
                    users = User.query.filter(or_(User.name.ilike(f'%{search_query}%'), User.last_name.ilike(f'%{search_query}%'))).all()
                else:
                    users = User.query.all()
    else:
        users = User.query.all()

    return render_template("users_and_search.html", search_form=search_form, users=users)


#profile uzytkownikow z widoku admina
@app.route('/user/<int:user_id>')
@admin_only
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('user_profile.html', user=user)


#edycja profilu uzytkownika z widoku admina
@app.route('/edit-user/<int:user_id>', methods=['GET', 'POST'])
@admin_only
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = AddUserForm(obj=user)
    errors = []

    existing_email = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()
    if existing_email and existing_email.id != user.id:
        errors.append("Ten adres e-mail jest już zarejestrowany.")

    existing_login = db.session.execute(db.select(User).where(User.login == form.login.data)).scalar()
    if existing_login and existing_login.id != user.id:
        errors.append("Ten login jest już zajęty.")

    existing_pesel = db.session.execute(db.select(User).where(User.pesel == form.pesel.data)).scalar()
    if existing_pesel and existing_pesel.id != user.id:
        errors.append("Ten numer PESEL już istnieje w bazie danych.")

    if errors:
        for error in errors:
            flash(error, 'error')
        return render_template('edit_user.html', form=form)
    

    if form.validate_on_submit():
        form.populate_obj(user)

        user.password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )

        db.session.commit()
        return redirect(url_for('user_profile', user_id=user.id))

    return render_template('edit_user.html', form=form, user=user)


#usuwanie profilu uzytkownika z bazy z widoku admina
@app.route('/user-delete/<int:user_id>', methods=['GET', 'DELETE'])
@admin_only
def user_delete(user_id):
    user = User.query.get_or_404(user_id)
    if user_id != 1: 
        try:
            db.session.delete(user)
            db.session.commit()
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            db.session.rollback()

    return redirect(url_for("user_search"))

### LOGOWANIE

@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if user:
            flash("Taki e-mail istnieje, zaloguj się!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("mainpage"))
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        password = form.password.data
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if not user:
            flash("E-mail nie istnieje, spróbuj ponownie.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            session['login_attempts'] = session.get('login_attempts', 0) + 1
            flash('Hasło niepoprawne, spróbuj ponownie.')
            
            if session['login_attempts'] >= 3:
                session.pop('login_attempts', None)  # Resetowanie prob logowania
                flash('Twoje konto zostało tymczasowo zablokowane.', 'error')

                time.sleep(5)

                return redirect(url_for('login'))
            
            return redirect(url_for('login'))
        else:
            login_user(user)
            session['login_attempts'] = 0
            return redirect(url_for('mainpage'))

    return render_template("login.html", form=form, current_user=current_user)


def is_password_required():
    if current_user.is_authenticated:
        if current_user.pass_ch_req == 1:
            return True  
    else:
        return False
    

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


def sendMail(recipient,password):
    msg = Message(subject='Odzyskiwanie hasła', sender='magazynek18@outlook.com', recipients=[recipient])
    msg.body = "Twoje jednorazowe hasło to  - " + password
    mail.send(msg)

    with open("mail.txt", "a") as file:
        file.write("Subject: " + msg.subject + "\n")
        file.write("From: " + msg.sender + "\n")
        file.write("To: " + ", ".join(msg.recipients) + "\n")
        file.write("Body: " + msg.body + "\n")

    return 


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():

    form = ForgotPasswordForm()
    if form.validate_on_submit():

        login = form.login.data
        email = form.email.data
        user = User.query.filter_by(login=login).first()
        if user and user.email == email:

            password = generate_password()
            if not is_used(user,password):
                set_password(user,password)
                sendMail(email,password)
                user.pass_ch_req = 1
                db.session.commit()

            flash('Nowe hasło zostało wysłane na podany email', 'success')

            #zmien wartosc pass_ch_req na 1
            return redirect(url_for('login'))

        else:
            flash('Nieprawidłowy login lub adres e-mail.', 'error')
            return render_template('forgot-password.html', form=form)

    return render_template('forgot-password.html', form=form)


def is_used(user,password):
    passwords = []
    password_history = user.password_history

    if user.password_history:
        passwords = password_history.split(", ")
        for password_hash in passwords:
            if check_password_hash(password_hash, password):
                flash("Podane hasło było już użyte")
                return True
        
    return False


def set_password(user,password):
    passwords = []
    newPasswordHash = generate_password_hash(
        password,
        method='pbkdf2:sha256',
        salt_length=8
    )

    if user.password_history:
        passwords = user.password_history.split(", ")

    passwords.insert(0, newPasswordHash)

    if len(passwords) > 3:
        passwords = passwords[:3]

    user.password_history = ", ".join(passwords)
    user.password = newPasswordHash

    db.session.commit()


def generate_password():
    password=''
    use_lowercase = 3
    use_uppercase = 3
    use_numbers = 2
    use_special_chars = 2
    special_chars = '-_!*#$&'

    password = ''.join(secrets.choice(string.ascii_lowercase) for _ in range(use_lowercase))
    password += ''.join(secrets.choice(string.ascii_uppercase) for _ in range(use_uppercase))
    password += ''.join(secrets.choice(string.digits) for _ in range(use_numbers))
    password += ''.join(secrets.choice(special_chars) for _ in range(use_special_chars))

    password_list = list(password)
    random.shuffle(password_list)
    password = ''.join(password_list)


    return password

@admin_only
@app.route('/adminpassword/<int:user_id>', methods=['GET', 'POST'])
def admin_passwordchange(user_id):
    user = User.query.get_or_404(user_id)
    form = EditProfileForm(obj=user)
    password = form.password.data

    if form.validate_on_submit():
        if not is_used(user,password):
            set_password(user,password)
            flash('Hasło zostało zmienione pomyślnie')

    return render_template('admin_passwordchange.html', form=form, user=user)


if __name__ == "__main__":

    app.run(debug=True, port=5001)
