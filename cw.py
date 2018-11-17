from flask import Flask, render_template, flash, redirect, url_for, session, request, abort
from datetime import datetime
from forms import RegForm, LoginForm, UpdateProfileForm, NewPostForm, SearchForm
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
	joinDate = db.Column(db.DateTime, default=datetime.utcnow(), nullable=False)
	wallPosts = db.relationship('WallPost', backref='poster', lazy=True)
	friends = db.relationship('Friend', backref='friend', lazy=True)

class WallPost(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	body = db.Column(db.Text, nullable=False)
	timeStamp = db.Column(db.DateTime, default=datetime.utcnow(), nullable=False)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Friend(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(20), unique=True, nullable=False)
	timeAdded = db.Column(db.DateTime, default=datetime.utcnow(), nullable=False)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Chat(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	

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

@app.route('/add/user/<string:otherUsername>')
def addUser(otherUsername):
	if session['loggedIn'] == True:
		if session['username'] != otherUsername:
			otherUser = User.query.filter_by(username=otherUsername).first()
                        user = User.query.filter_by(username=session['username']).first()
			if otherUser != None:
				friend = Friend(username=otherUsername, user_id=user.id)
				db.session.add(friend)
				db.session.commit()
				flash("User added as friend", "success")
				return redirect('/profile')
			else:
				flash("User does not exist", "danger")
				return redirect("/profile")
		else:
			flash("You cannot add yourself as a friend", "danger")
			return redirect('/profile')
	else:
		flash("Please sign in first", "warning")
	return redirect('/login')		

@app.route("/profile/<string:otherUser>")
def otherProfile(otherUser):
	 if session.get('loggedIn') == True:
		if session['username'] != otherUser:
	                user = User.query.filter_by(username=otherUser).first()
        	        wallposts = user.wallPosts
         	        wallposts.reverse()
                	return render_template('profile.html', user=user, wallPosts=wallposts, ownProfile=False)
		else:
			return redirect('/profile')
         else:
                flash("Please sign in first", "warning")
         return redirect("/login")

@app.route("/search/user", methods=['GET','POST'])
def userSearch():
	if session.get('loggedIn') == True:
		form = SearchForm()
		if request.method == 'POST':
			if form.validate_on_submit():
				search = form.username.data
				url = "/search/" + search + "/results"
				return redirect(url)
		return render_template('search.html', form=form)
	else:
                flash("Please sign in first", "warning")
	return redirect("/login")


@app.route("/search/<string:search>/results")
def searchResults(search):
	if session.get('loggedIn') == True:
		if search != "":
			matchedUser = User.query.filter_by(username=search).first()
	        	similarMatches = User.query.filter(User.username.ilike('%{}%'.format(search)))
			similarMatchesCount = similarMatches.count()
			return render_template('results.html', matchedUser=matchedUser, similarMatches=similarMatches, currentUsername=session['username'], search=search, similarMatchesCount=similarMatchesCount)
		else:
			abort(404)
	else:
                flash("Please sign in first", "warning")
        return redirect("/login")

	

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
				session['user_id'] = user.id
                                session['email'] = user.email
			return redirect('/')
		return render_template('register.html', form=form)
	except Exception as error:
		form=RegForm()
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
	return redirect('/')

@app.route("/wallPost/new", methods=['GET','POST'])
def createPost():
	if session.get('loggedIn') == True:
		form = NewPostForm()
		if form.validate_on_submit():
			newPost = WallPost(body=form.body.data, user_id=session['user_id'])
			if request.method == 'POST':
				db.session.add(newPost)
				db.session.commit()
			return redirect('/profile')	
		return render_template('newPost.html', form=form)
        else:
                flash("Please sign in first", 'danger')
        return render_template('login.html', form=form)

@app.route("/profile")
def profile():	
	if session.get('loggedIn') == True:
		user = User.query.filter_by(username=session['username']).first()
		wallposts = user.wallPosts
		wallposts.reverse()
		friends = user.friends
		return render_template('profile.html', user=user, wallPosts=wallposts, ownProfile=True, friendsList=friends)
	else:
		flash("Please sign in first", "warning")
                return redirect("/login")

@app.route("/profile/update/<int:user_id>", methods=['GET', 'POST'])
def updateProfile(user_id):
	form=UpdateProfileForm()
        if session.get('loggedIn') == True:
		if user_id == session['user_id']:
			if request.method == 'POST':
				user = User
			return redirect('/profile')
       		else:
	       		flash("You do not have permission to edit this profile", "danger")
                	return redirect("/")
        else:
                flash("Please sign in first", "warning")
                return redirect("/login")
        return render_template('updateProfile.html', form=form)

@app.route("/wallpost/view/<int:wallPost_id>")
def viewPost(wallPost_id):
	wallPost = WallPost.query.get_or_404(wallPost_id)
	return render_template('wallPost.html', wallPost = wallPost)

@app.route("/wallpost/delete/<int:wallPost_id>")
def deletePost(wallPost_id):
	if session.get('loggedIn') == True:
		wallPost = WallPost.query.get_or_404(wallPost_id)
		if wallPost.user_id == session['user_id']:
			db.session.delete(wallPost)
        		db.session.commit()
			flash("Post Deleted", "success")
		else:
			flash("You do not have permission to delete this post", "danger")
			return redirect("/")
	else:
		flash("Please sign in first", "warning")
		return redirect("/login")
	return redirect('/profile')

if __name__ == "__main__":
        init(app)
        app.run(debug = True)

