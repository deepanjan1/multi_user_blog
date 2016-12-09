import os

import jinja2
import webapp2
import re
import hmac
import random
import hashlib
import string

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), 
								autoescape = True)

secret = "bJXzCSW#n.Re{%WL+8G;/:hxn/t6"

#Hashing functions
def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

def make_salt():
	return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = ""):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name+pw+salt).hexdigest()
	return '%s,%s' % (h,salt)

def valid_pw(name, pw, h):
	salt = h.split(',')[1]
	return h == make_pw_hash(name, pw, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

#Main Handler
class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (str(name), str(cookie_val)))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('userid', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'userid=; Path=/')

	def initiatlize(self, *a, **kw):
		webapp2.RequestHandler.initiatlize(self,*a,**kw)
		uid = self.read_secure_cookie('userid')
		self.user = uid and Users.by_id(int(uid))

	def get_post_by_id(self, post_id):
		return Post_Entry.get_by_id(int(post_id))

#Blog and Users Table
class Post_Entry(db.Model):
	subject = db.StringProperty(required = True)
	blog_content = db.TextProperty(required = True)
	creator = db.StringProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

class Users(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty(required = False)

	@classmethod
	def by_id(cls, uid):
	    return cls.get_by_id(uid)

	@classmethod
	def by_name(cls, name):
	    u = cls.all().filter('username =', name).get()
	    return u

	@classmethod
	def register(cls, name, pw, email = None):
	    pw_hash = make_pw_hash(name, pw)
	    return cls( username = name,
	                password = pw_hash,
	                email = email)

	@classmethod
	def login(cls, name, pw):
	    u = cls.by_name(username)
	    if u and valid_pw(name, pw, u.password):
	        return u

#Page Handlers
class MainPage(Handler):
	def get(self):
		entries = db.GqlQuery("select * from Post_Entry order by created desc limit 10")
		self.render('index.html', entries=entries)
	def post(self):
		if self.request.get('edit'):
			post = self.get_post_by_id(self.request.get('edit'))
			if self.read_secure_cookie('userid') == post.creator:
				self.redirect('/blog/edit_post/%s' % str(post.key().id()))
			else:
				self.redirect('/blog/edit_post/error')
		elif self.request.get('delete'):
			post = self.get_post_by_id(self.request.get('delete'))
			if self.read_secure_cookie('userid') == post.creator:
				self.redirect('/blog/delete_post/%s' % str(post.key().id()))
			else:
				self.redirect('/blog/delete_post/error')
			

class NewPost(Handler):
	def render_newpost(self, subject="", blog_content="", error=""):
		self.render("newpost.html", subject=subject, blog_content=blog_content, error=error)
	def get(self):
		self.render_newpost()
	def post(self):
		subject = self.request.get('subject')
		blog_content = self.request.get('blog_content')
		creator = self.read_secure_cookie('userid')
		if subject and blog_content:
			a = Post_Entry(subject = subject, blog_content = blog_content, creator = creator)
			a.put()
			self.redirect('/blog/%s' % str(a.key().id()))
		else:
			error  = "Please submit both a subject and blog content."
			self.render_newpost(subject, blog_content, error)

class PostPage(Handler):
	def get(self, post_id):
		key = db.Key.from_path('Post_Entry', int(post_id))
		post = db.get(key)
		user = self.read_secure_cookie('userid')
		self.render('permalink.html', post = post, user = user)
	def post(self, post_id):
		if self.request.get('edit'):
			post = self.get_post_by_id(self.request.get('edit'))
			if self.read_secure_cookie('userid') == post.creator:
				self.redirect('/blog/edit_post/%s' % str(post.key().id()))
			else:
				self.redirect('/blog/edit_post/error')
		elif self.request.get('delete'):
			post = self.get_post_by_id(self.request.get('delete'))
			if self.read_secure_cookie('userid') == post.creator:
				self.redirect('/blog/delete_post/%s' % str(post.key().id()))
			else:
				self.redirect('/blog/delete_post/error')

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S+@[\S]+\.[\S]+$')
def valid_email(email):
	return not email or EMAIL_RE.match(email)

class Signup(Handler):
	def render_signup(self, username = "", password = "", verify = "", email = "", error_username = "",
					  error_password = "", error_email = "", error_username_exists = ""):
		self.render('signup.html', username = username, password = password, verify = verify, email = email, 
					error_username = error_username, error_password = error_password, error_email = error_email, error_username_exists = error_username_exists)	
	
	def get(self):
		# if self.read_secure_cookie('userid'):
		# 	self.redirect('/blog/welcome')
		self.render_signup()
	
	def post(self):
		have_error = False
		name = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')
		
		params = dict(username = name, 
					  email = email)
		
		u = Users.all().filter('username =', name).get()

		if not valid_username(name):
			params['error_username'] = "That's not a valid username."
			have_error = True
		if not valid_password(password):
			params['error_password'] = "That's not a valid password or your password did not match."
			have_error = True
		elif password != verify:
			params['error_password'] = "That's not a valid password or your password did not match."
			have_error = True
		if not valid_email(email):
			params['error_email'] = "That's not a valid email."
			have_error = True
		if u:
			params['error_username_exists'] = "This username already exists!"
			have_error = True
		
		if have_error:
			self.render_signup(**params)
		else:
			hash_pw = make_pw_hash(name, password)
			user = Users(username = name, password = hash_pw, email = email)
			user.put()
			self.login(user)
			self.redirect('/blog/welcome')
			

class Welcome(Handler):
	def get(self):
		if self.read_secure_cookie('userid'):
			user_id = self.read_secure_cookie('userid')
			key = db.Key.from_path('Users', int(user_id))
			user = db.get(key)
			self.render('welcome.html', username = user.username)
		else:
			self.redirect('/blog/signup')

class Login(Handler):
	def render_login(self, username = "", password = "", error = ""):
		self.render('login.html', username = username, password = password, error = error)
	def get(self):
		self.render_login()
	def post(self):
		name = self.request.get('username')
		password = self.request.get('password')
		u = Users.all().filter('username =', name).get()

		if valid_pw(name, password, u.password):
			self.login(u)
			self.redirect('/blog/welcome')
		else:
			self.render_login(username = name, error = "Sorry.  Your user and password combination did not match!")

class Logout(Handler):
	def get(self):
		self.logout()
		self.redirect('/blog/signup')

class EditPost(Handler):
	def get(self, post):
		key = db.Key.from_path('Post_Entry', int(post))
		post = db.get(key)
		self.render('edit_post.html', blog = post)
	def post(self, post):
		subject = self.request.get('subject')
		blog_content = self.request.get('blog_content')
		post_id = self.request.get('Save')
		if post_id:
			post = Post_Entry.get_by_id(int(post_id))
			post.subject = subject
			post.blog_content = blog_content
			post.put()
			self.redirect('/blog/%s' % str(post.key().id()))
		else:
			error  = "Please submit both a subject and blog content."
			#self.render_newpost(subject, blog_content, error)

class DeletePost(Handler):
	def get(self, post):
		key = db.Key.from_path('Post_Entry', int(post))
		post = db.get(key)
		self.render('delete_post.html', blog = post)
	def post(self, post):
		if self.request.get('Delete'):
			post = self.get_post_by_id(self.request.get('Delete'))
			post.delete()
			self.redirect('/blog/post_update')
		elif self.request.get('Cancel'):
			self.redirect('/blog/')

class ErrorPage(Handler):
	def get(self):
		self.render('error_page.html')

class StatusUpdate(Handler):
	def get(self):
		self.render('updated.html')


app = webapp2.WSGIApplication([('/blog/?', MainPage),
	                           ('/blog/newpost', NewPost),
	                           ('/blog/([0-9]+)', PostPage),
	                           ('/blog/signup', Signup), 
	                           ('/blog/welcome', Welcome), 
	                           ('/blog/login', Login), 
	                           ('/blog/logout', Logout),
	                           ('/blog/edit_post/([0-9]+)', EditPost),
	                           ('/blog/edit_post/error', ErrorPage),
	                           ('/blog/delete_post/([0-9]+)', DeletePost),
	                           ('/blog/delete_post/error', ErrorPage),
	                           ('/blog/post_update', StatusUpdate),
	                           ], 
								debug=True)
