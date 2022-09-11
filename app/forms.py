from ast import Pass
from flask import Flask
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import BooleanField, StringField, EmailField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length, Email

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(), Length(min=5, max=30)
    ])
    email = EmailField('Email', validators=[
        DataRequired(), Email()
    ])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(), EqualTo('password')
    ])
    submit = SubmitField('Sign Up')
    recaptcha = RecaptchaField()