
'''Importing Library Functions'''
from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_navigation import Navigation
from flask_login import LoginManager,UserMixin,login_user,login_required,logout_user,current_user
from werkzeug.security import generate_password_hash,check_password_hash

#this library functions are imported to generate encrypted passwords the last one
#without the last one can also be done but password will be visible

#Configuring all the Flask Values to connect database and bootstrap
app = Flask(__name__)
app.config['SECRET_KEY'] = 'Mysecretkey123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://///home/subhro/Desktop/FlaskProject/database.db'
Bootstrap(app)
nav = Navigation(app)
db = SQLAlchemy(app)

#Create a Navigation Bar
nav.Bar('top', [
    nav.Item('Home', 'index')
    ])
#initializing the login_managerwith the app
login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#setting up a decorator
@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))


#Create a db Model/Table as ORM as in SQL for Users and using UserMixin to get full functionality of flask Login'''
class User(UserMixin,db.Model):
	id = db.Column(db.Integer,primary_key=True)
	username=db.Column(db.String(80),unique=True)
	password=db.Column(db.String(80))
	email=db.Column(db.String(80),unique=True)
	fullname=db.Column(db.String(80))
	phone=db.Column(db.String(10),unique=True)

#Create a db Model/Table as in SQLAlchemy for Admin
class Admin(db.Model):
	id = db.Column(db.Integer,primary_key=True)
	adminusername=db.Column(db.String(80),unique=True)
	adminpassword=db.Column(db.String(80))

#defining all form data in the form or templates
class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(),Length(min=4,max=80)])
    password = PasswordField('password', validators=[InputRequired(),Length(min=8,max=80)])
    remember = BooleanField('remember me')

class AdminLoginForm(FlaskForm):
	adminusername = StringField('adminusername',validators=[InputRequired(),Length(min=4,max=80)])
	adminpassword = PasswordField('adminpassword',validators=[InputRequired(),Length(min=6,max=80)])

class UserSignUp(FlaskForm):
	username = StringField('username',validators=[InputRequired(),Length(min=4,max=80)])
	password = PasswordField('password',validators=[InputRequired(),Length(min=8,max=80)])
	email = StringField('email',validators=[InputRequired(),Length(min=4,max=80)])
	fullname = StringField('fullname',validators=[InputRequired(),Length(min=3,max=8)])
	phone = StringField('phone',validators=[InputRequired(),Length(min=10,max=10)])

class AdminCreate(FlaskForm):
	username = StringField('username',validators=[InputRequired(),Length(min=4,max=80)])
	password = PasswordField('password',validators=[InputRequired(),Length(min=8,max=80)])
	email = StringField('email',validators=[InputRequired(),Length(min=4,max=80)])
	fullname = StringField('fullname',validators=[InputRequired(),Length(min=3,max=8)])
	phone = StringField('phone',validators=[InputRequired(),Length(min=10,max=10)])

class DeleteUser(FlaskForm):
	username = StringField('username',validators=[InputRequired(),Length(min=4,max=80)])

# @app.route() is used to transfer user to different web pages
# Routing to Index Page
@app.route('/')
def index():
    return render_template('index.html')

# Routing to User Login Page
@app.route('/login' , methods = ['GET','POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user=User.query.filter_by(username=form.username.data).first()
		if user:
			if check_password_hash(user.password,form.password.data):
				#this below lone acts as session without that you cannopt go to dashboard
				login_user(user,remember=form.remember.data)
				return redirect(url_for('dashboard'))
		return redirect(url_for('login','Invalid Credentials'))
	return render_template('login.html',form=form)

# Routing to Admin Login Page
@app.route('/adminlogin', methods = ['GET','POST'])
def adminlogin():
	form1 = AdminLoginForm()
	if form1.validate_on_submit:
		admin=Admin.query.filter_by(adminusername=form1.adminusername.data).first()
		if admin:
			if admin.adminpassword == form1.adminpassword.data:
				return redirect(url_for('admindashboard'))
			return redirect(url_for('index'),'Invalid Credentials')
	return render_template('adminlogin.html',form=form1)

# Routing to User signup Page
#method=sha256 is security encryption for passwords to be converted to cipher code
@app.route('/signup',methods = ['GET','POST'])
def signup():
	form2=UserSignUp()
	if form2.validate_on_submit():
		hashed_password=generate_password_hash(form2.password.data,method='sha256')
		new_user = User(username=form2.username.data,email=form2.email.data,password=hashed_password,phone=form2.phone.data,fullname=form2.fullname.data)
		db.session.add(new_user)
		db.session.commit()
		return redirect(url_for('login'))
	return render_template('signup.html',form=form2)

@app.route('/admincreate',methods = ['GET','POST'])
def admincreate():
	form2=AdminCreate()
	if form2.validate_on_submit():
		hashed_password=generate_password_hash(form2.password.data,method='sha256')
		new_user = User(username=form2.username.data,email=form2.email.data,password=hashed_password,phone=form2.phone.data,fullname=form2.fullname.data)
		db.session.add(new_user)
		db.session.commit()
		return redirect(url_for('admindashboard'))
	return render_template('admincreate.html',form=form2)

#Routing to Delete User Page
@app.route('/deleteuser',methods = ['GET','POST'])
def deleteuser():
	form2=DeleteUser()
	if form2.validate_on_submit():
		new_user = User.query.filter_by(username=form2.username.data).first()
		db.session.delete(new_user)
		db.session.commit()
		return redirect(url_for('admindashboard'))
	return render_template('deleteuser.html',form=form2)


#Routing to User Dashboard Page
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html',name=current_user.username,email=current_user.email,phone=current_user.phone,fullname=current_user.fullname)

#Routing to Admin Dashboard Page
@app.route('/admindashboard')
def admindashboard():
	result = User.query.all()
	return render_template('admindashboard.html',result=result)


@app.route('/logout')
@login_required
def logout():
	return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
