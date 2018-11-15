from flask import Flask, render_template, flash, redirect, url_for, session, request
from datetime import datetime
from forms import RegForm, LoginForm, ProfileForm, NewPostForm
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import sha256_crypt

app = Flask(__name__)
app.secret_key = '\xeb\x10\rv\xf3\x00\x81\xa7\x83\xcc\x9e\xd8\x87\x16\x16\xc4!\x94\xb2\xaa%\xebDo'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///save.db'
db = SQLAlchemy(app)

class User(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(20), unique=True, nullable=False)
	email = db.Column(db.String(50), unique=True, nullable=False)
	profilePic = db.Column(db.String(20), nullable=False, default='default.jpg' )
	password = db.Column(db.String(50), nullable=False)
	wallPosts = db.relationship('wallPost', backref='poster', lazy=True)

class wallPost(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	body = db.Column(db.Text, nullable=False)
	timeStamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

def validateUser(user):
	try:
		validator = User.query.filter_by(username=user.username).first()
        	if validator:
	               	raise Exception('Sorry, that username is already in use')
		validator = User.query.filter_by(email=user.email).first()
              	if validator:
  	              raise Exception('Sorry, that email is already in use')
	except Exception as error:
		raise Exception(error.message)

@app.route("/")
def home():
	return render_template('home.html')

@app.route("/search/<searchTerm>")
def userSearch(searchTerm):
	search = searchTerm
	return "tada"

@app.route("/register", methods=['GET','POST'])
def register():
	try:
		form = RegForm()
		if form.validate_on_submit():
			encryptedPassword = sha256_crypt.encrypt(form.password.data)
			user = User(username=form.username.data, email=form.email.data, password=encryptedPassword)
			validateUser(user)
			db.session.add(user)
			db.session.commit()
			flash(u'Keep connected, stay safe, and enjoy!', 'success')
			if request.method == 'POST':
                                session['loggedIn'] = True
				session['username'] = user.username
			return redirect(url_for('home'))
		return render_template('register.html', form=form)
	except Exception as error:
		flash(error.message, 'danger')
		return render_template('register.html', form=form)	

@app.route("/login", methods=['GET','POST'])
def login():
        form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user and sha256_crypt.verify(form.password.data, user.password):
			if request.method == 'POST':
                                session['loggedIn'] = True
				session['user_id'] = user.id
                                session['username'] = user.username
				session['email'] = user.email
				flash("Nice to see you again", 'success')
			return redirect(url_for('home'))
		else:
			flash("Invalid details", 'danger')
        return render_template('login.html', form=form)

@app.route("/logout")
def logout():
	session['loggedIn'] = False
	session.pop('user_id', None)
	session.pop('username', None)
	session.pop('email', None)
	flash('You have been successfully logged out', 'success')
	return redirect(url_for('home'))

@app.route("/wallPost/new", methods=['GET','POST'])
def createPost():
	form = NewPostForm()
	if form.validate_on_submit():
		newPost = wallPost(body=form.body.data, user_id=session['user_id'])
		if request.method == 'POST':
			db.session.add(newPost)
			db.session.commit()
		return redirect('/profile')	
	return render_template('newPost.html', form=form)

@app.route("/profile")
def profile():	
	user = User.query.filter_by(username=session['username']).first()
	profilePic = user.profilePic
	wallposts = user.wallPosts
	return render_template('profile.html', username=session['username'], profilePic=profilePic, wallPosts = wallposts)

#@app.route("/search/<searchTerm>")
#def search(searchTerm):
#	search = searchTerm
#	return search

if __name__ == "__main__":
        init(app)
        app.run(debug = True)

