from crypt import methods
import email
from email.message import Message
from flask import render_template, url_for, flash, redirect, request
from flask_login import current_user
from app import app, db, bcrypt
from app.forms import RegistrationForm, LoginForm, EmailTemplate
from app.models import User, EmailSent
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Mail, Message

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'youjustgotzinged@gmail.com'
app.config['MAIL_PASSWORD'] = 'wnedoxtnbfaabgcf'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail(app)

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
        return redirect(url_for('dashboard', currentuser=current_user.username))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('dashboard', currentuser=current_user.username))
        else:
            flash("Login failed, username or password wrong lol")
    return render_template("login.html", form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard', currentuser=current_user.username))
    form = RegistrationForm()
    if request.method == 'POST':
        username = User.query.filter_by(username=form.username.data).first()
        email = User.query.filter_by(email=form.email.data).first()
        if email is not None:
            flash("This email is taken!")
            if username is not None:
                flash("And this username is taken!")
        elif username is not None:
            flash("This username is taken")
        else:
            hashed_password = bcrypt.generate_password_hash(form.password.data)
            user = User(username=form.username.data, email=form.email.data, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash('You account has been created!')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/dashboard/<currentuser>')
def dashboard(currentuser):
    database = EmailSent.query.filter_by(user_id=current_user.id)
    return render_template("dashboard.html", username=current_user.username, database=database)

@app.route('/newpost', methods=['POST', 'GET'])
def newpost():
    form = EmailTemplate()
    database_for_email = EmailSent()
    if form.validate_on_submit():
        email_list = form.recipients.data.split(', ')
        msg = Message(form.subject.data,
                  sender="youjustgotzinged@gmail.com",
                  recipients=email_list)
        msg.body = form.message.data
        email_list = ",".join(email_list)
        print(email_list)
        email_data = EmailSent(recipients=email_list, subject=form.subject.data, message=form.message.data, user_id=current_user.id)
        db.session.add(email_data)
        db.session.commit()
        return redirect(url_for('dashboard', currentuser=current_user.username))
    return render_template("new_post.html", form=form, user=current_user, emails_sent=database_for_email)


@app.route('/delete', methods=["GET", "POST"])
def delete():
    database = User()
    if request.method == "POST":
        for user in database.query.all():
            if request.form['delete'] == "Delete " + user.username:
                User.query.filter_by(username=user.username).delete()
                EmailSent.query.filter_by(user_id=user.id).delete()
                db.session.commit()
    return render_template('delete.html', database=database)

@app.route('/logout', methods=["POST", "GET"])
def logout():
    logout_user()
    flash("You are succesfully logged out!")
    return render_template('logout.html')

@app.errorhandler(404)
def not_found_error(error):
    return "Whoops! <br> <a href='/'>Return Home!</a>"


@app.errorhandler(500)
def internal_error():
    db.sesssion.rollback()
    return "Whoops! <br> <a href='/'>Return Home!</a>"