from crypt import methods
from flask import render_template, url_for, flash, redirect, request
from flask_login import current_user
import flask_login
from app import app, db, bcrypt
from app.forms import RegistrationForm, LoginForm
from app.models import User
from flask_login import login_user, current_user, logout_user, login_required

#Making a simple log in app, that returns your data
@app.route('/', methods=["POST", "GET"])
def landing_page():
    if request.method == 'POST':
        if request.form['submit'] == 'Login':
            return redirect(url_for('login'))

        elif request.form['submit'] == 'Register':
            return redirect(url_for('register'))

        elif request.form['submit'] == 'Delete':
            return redirect(url_for('delete'))

        else:
            return redirect(url_for('logout'))
    return render_template('index.html')

@app.route('/login', methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('hello_user'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('hello_user'))
        else:
            flash("Login failed, username or password wrong lol")
    return render_template("login.html", form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('hello_user'))
    form = RegistrationForm()
    if request.method == 'POST':
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('You account has been created!')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/hello_user', methods=["GET", "POST"])
def hello_user():
    name = str(current_user.username)
    return render_template('hello_user.html', name=name)

@app.route('/delete', methods=["GET", "POST"])
def delete():
    database = User()
    if request.method == "POST":
        for user in database.query.all():
            if request.form[user.username] == "Delete User":
                User.query.filter_by(username=user.username).delete()
                db.session.commit()
    return render_template('delete.html', database=database)

@app.route('/logout', methods=["POST", "GET"])
def logout():
    logout_user()
    flash("You are succesfully logged out!")
    return render_template('logout.html')