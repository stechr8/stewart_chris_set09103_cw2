from wtforms import TextField, PasswordField, SubmitField, BooleanField
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Length, Email, EqualTo

class RegForm(FlaskForm):
	username = TextField('Username', validators=[DataRequired(), Length(min=4, max=20)])
	password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=20)])
	email = TextField('Email', validators=[DataRequired(), Email()])
	confirmPassword = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])

	submit = SubmitField('Register')

class LoginForm(FlaskForm):
        email = TextField('Email', validators=[DataRequired(), Email()])
        password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=20)])
	rememberMe = BooleanField('Remember me')

        submit = SubmitField('Login')

