from google.appengine.ext import db

# Users db.Model for each registered person
class Users(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty(required = False)

# Post db.Model for each entry
class Post_Entry(db.Model):
	subject = db.StringProperty(required = True)
	blog_content = db.TextProperty(required = True)
	like = db.IntegerProperty(required = False, default = 0)
	creator = db.StringProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

# Comments db.Model for each post
class Comments(db.Model):
	comment = db.TextProperty(required = True)
	post = db.IntegerProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
	commenter = db.StringProperty(required = True)

# Likes db.Model for each post
class Likes(db.Model):
	liker = db.StringProperty(required = True)
	post = db.StringProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)