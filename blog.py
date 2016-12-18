import os

import jinja2
import webapp2
import re
import hmac
import random
import hashlib
import string
import config

from models import Post_Entry, Users, Comments, Likes

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# Secret is held in an separate file
SECRET = config.secret

# Hashing functions


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw, salt=""):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)

# Functions for validating username, email, and passwords
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)

# Main Handler


class Handler(webapp2.RequestHandler):
    """
method/class name: Main Handler
Args:
    webapp2.RequestHandler: from google cloud
Returns:
    various functions return different values
"""

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie', '%s=%s; Path=/' %
            (str(name), str(cookie_val)))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('userid', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'userid=; Path=/')

    def initiatlize(self, *a, **kw):
        webapp2.RequestHandler.initiatlize(self, *a, **kw)
        uid = self.read_secure_cookie('userid')
        self.user = uid and Users.by_id(int(uid))

    def get_post_by_id(self, post_id):
        return Post_Entry.get_by_id(int(post_id))

    def get_comment_by_id(self, comment_id):
        return Comments.get_by_id(int(comment_id))

    def like_post(self, post_id, user):
        self.logged_in_user()
        all_likes = Likes.all()
        this_like = all_likes.filter(
            "post =", post_id).filter(
            "liker =", user).get()
        post = self.get_post_by_id(post_id)
        if this_like:
            db.delete(this_like)
            post.like = post.like - 1
            post.put()
            return False
        else:
            a = Likes(liker=user, post=post_id)
            a.put()
            post.like = post.like + 1
            post.put()
            return True

    def logged_in_user(self):
        if not self.read_secure_cookie('userid'):
            self.redirect('/blog/login')
        else:
            pass

    def post_exists(self, post):
    	if not post:
    		self.error(404)

	def comment_exists(self,comment):
		if not comment:
			self.error(404)


# Page Handlers


class MainPage(Handler):
    """
method/class name: MainPage (Blog homepage)
Args:
    Handler
Returns:
    The '/blog' page and retrieves blog posts
"""

    def get(self):
        liker = self.read_secure_cookie('userid')
        entries = db.GqlQuery(
            "select * from Post_Entry order by created desc limit 10")
        self.render('index.html', entries=entries)

    def post(self):
        if self.request.get('edit'):
            post = self.get_post_by_id(self.request.get('edit'))
            if self.read_secure_cookie('userid') == post.creator:
                self.redirect('/blog/edit-post/%s' % str(post.key().id()))
            else:
                self.redirect('/blog/edit-post/error')
        elif self.request.get('delete'):
            post = self.get_post_by_id(self.request.get('delete'))
            if self.read_secure_cookie('userid') == post.creator:
                self.redirect('/blog/delete-post/%s' % str(post.key().id()))
            else:
                self.redirect('/blog/delete-post/error')
        elif self.request.get('like'):
            post_id = self.request.get('like')
            post = self.get_post_by_id(self.request.get('like'))
            user = self.read_secure_cookie('userid')
            if self.read_secure_cookie('userid') and self.read_secure_cookie(
                    'userid') != post.creator:
                trigger = self.like_post(post_id, user)
                if not trigger:
                    self.redirect('/blog/like-status-removed')
                else:
                    self.redirect('/blog/like-status-added')

            elif self.read_secure_cookie('userid') == post.creator:
                self.redirect('/blog/like-post/error')
            elif not self.read_secure_cookie('userid'):
                self.redirect('/blog/login')
        elif self.request.get('comment'):
            post = self.get_post_by_id(self.request.get('comment'))
            self.redirect('/blog/%s' % str(post.key().id()))


class NewPost(Handler):

    def render_newpost(self, subject="", blog_content="", error=""):
        self.render(
            "newpost.html",
            subject=subject,
            blog_content=blog_content,
            error=error)

    def get(self):
        self.logged_in_user()
        self.render_newpost()

    def post(self):
        self.logged_in_user()
        subject = self.request.get('subject')
        blog_content = self.request.get('blog_content')
        creator = self.read_secure_cookie('userid')
        if subject and blog_content:
            a = Post_Entry(
                subject=subject,
                blog_content=blog_content,
                creator=creator)
            a.put()
            self.redirect('/blog/%s' % str(a.key().id()))
        else:
            error = "Please submit both a subject and blog content."
            self.render_newpost(subject, blog_content, error)


class PostPage(Handler):

    def get(self, post_id):
        key = db.Key.from_path('Post_Entry', int(post_id))
        post = db.get(key)
        self.post_exists(post)
        user = self.read_secure_cookie('userid')
        comments = db.GqlQuery(
            "select * from Comments where post = %s order by created desc" %
            str(post_id))
        self.comment_exists(comments)
        self.render('permalink.html', post=post, user=user, comments=comments)

    def post(self, post_id):
        self.logged_in_user()
        self.post_exists()
        if self.request.get('edit'):
            post = self.get_post_by_id(self.request.get('edit'))
            if self.read_secure_cookie('userid') == post.creator:
                self.redirect('/blog/edit-post/%s' % str(post.key().id()))
            else:
                self.redirect('/blog/edit-post/error')
        elif self.request.get('delete'):
            post = self.get_post_by_id(self.request.get('delete'))
            if self.read_secure_cookie('userid') == post.creator:
                self.redirect('/blog/delete-post/%s' % str(post.key().id()))
            else:
                self.redirect('/blog/delete-post/error')
        elif self.request.get('like'):
            post_id = self.request.get('like')
            post = self.get_post_by_id(self.request.get('like'))
            user = self.read_secure_cookie('userid')
            if self.read_secure_cookie('userid') and self.read_secure_cookie(
                    'userid') != post.creator:
                trigger = self.like_post(post_id, user)
                if not trigger:
                    self.redirect('/blog/like-status-removed')
                else:
                    self.redirect('/blog/like-status-added')
            elif self.read_secure_cookie('userid') == post.creator:
                self.redirect('/blog/like-post/error')
            elif not self.read_secure_cookie('userid'):
                self.redirect('/blog/login')
        # Create Comment
        elif self.request.get('make_comment'):
            comment = self.request.get('make_comment')
            post = int(self.request.get('post'))
            commenter = self.read_secure_cookie('userid')
            a = Comments(comment=comment, post=post, commenter=commenter)
            self.comment_exists(a)
            a.put()
            self.redirect('/blog/comment-update/%s' % str(post))
        # Edit Comment
        elif self.request.get('edit_comment'):
            comment_id = self.request.get('edit_comment')
            comment = self.get_comment_by_id(comment_id)
            self.comment_exists(comment)
            if self.read_secure_cookie('userid') == comment.commenter:
                self.redirect('/blog/comment-edit/%s' % comment_id)
            else:
                self.redirect('/blog/edit-post/error')
        # Delete Comment
        elif self.request.get('delete_comment'):
            comment_id = self.request.get('delete_comment')
            comment = self.get_comment_by_id(comment_id)
            self.comment_exists(comment)
            if self.read_secure_cookie('userid') == comment.commenter:
                self.redirect('/blog/comment-delete/%s' % comment_id)
            else:
                self.redirect('/blog/edit-post/error')


class Signup(Handler):

    def render_signup(
            self,
            username="",
            password="",
            verify="",
            email="",
            error_username="",
            error_password="",
            error_email="",
            error_username_exists=""):
        self.render(
            'signup.html',
            username=username,
            password=password,
            verify=verify,
            email=email,
            error_username=error_username,
            error_password=error_password,
            error_email=error_email,
            error_username_exists=error_username_exists)

    def get(self):
        self.render_signup()

    def post(self):
        have_error = False
        name = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username=name,
                      email=email)

        u = Users.all().filter('username =', name).get()

        if not valid_username(name):
            params['error_username'] = "That's not a valid username."
            have_error = True
        if not valid_password(password):
            params[
                'error_password'] = "That's not a valid password or your password did not match."
            have_error = True
        elif password != verify:
            params[
                'error_password'] = "That's not a valid password or your password did not match."
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
            user = Users(username=name, password=hash_pw, email=email)
            user.put()
            self.login(user)
            self.redirect('/blog/welcome')


class Welcome(Handler):

    def get(self):
        if self.read_secure_cookie('userid'):
            user_id = self.read_secure_cookie('userid')
            key = db.Key.from_path('Users', int(user_id))
            user = db.get(key)
            self.render('welcome.html', username=user.username)
        else:
            self.redirect('/blog/signup')


class Login(Handler):

    def render_login(self, username="", password="", error=""):
        self.render(
            'login.html',
            username=username,
            password=password,
            error=error)

    def get(self):
        self.render_login()

    def post(self):
        name = self.request.get('username')
        password = self.request.get('password')
        u = Users.all().filter('username =', name).get()
        if u:
        	if valid_pw(name, password, u.password):
        		self.login(u)
        		self.redirect('/blog/welcome')
        else:
            self.render_login(
                username=name,
                error="Sorry.  Your user and password combination did not match!")


class Logout(Handler):

    def get(self):
        self.logout()
        self.redirect('/blog/signup')


class EditPost(Handler):

    def get(self, post):
        self.logged_in_user()
        key = db.Key.from_path('Post_Entry', int(post))
        post = db.get(key)
        self.post_exists(post)
        if self.read_secure_cookie('userid') == post.creator:
            self.render('edit_post.html', blog=post)
        else:
            self.redirect('/blog/login')

    def post(self, post):
        self.logged_in_user()
        subject = self.request.get('subject')
        blog_content = self.request.get('blog_content')
        post_id = self.request.get('Save')
        post = Post_Entry.get_by_id(int(post_id))
        self.post_exists(post)
        if self.read_secure_cookie('userid') == post.creator:
            if post_id:
                post.subject = subject
                post.blog_content = blog_content
                post.put()
                self.redirect('/blog/%s' % str(post.key().id()))
            elif self.request.get('Cancel'):
                self.redirect('/blog/')
        else:
            self.redirect('/blog/edit-post/error')


class DeletePost(Handler):

    def get(self, post):
        self.logged_in_user()
        key = db.Key.from_path('Post_Entry', int(post))
        post = db.get(key)
        self.post_exists(post)        
        if self.read_secure_cookie('userid') == post.creator:
            self.render('delete_post.html', blog=post)
        else:
            self.redirect('/blog/edit-post/error')

    def post(self, post):
        self.logged_in_user()        
        post = self.get_post_by_id(self.request.get('Delete'))
        self.post_exists(post)
        if self.read_secure_cookie('userid') == post.creator:
            if self.request.get('Delete'):
                post.delete()
                self.redirect('/blog/post-update')
            elif self.request.get('Cancel'):
                self.redirect('/blog/')
        else:
            self.redirect('/blog/edit-post/error')


class CommentDelete(Handler):

    def get(self, comment_id):
        self.logged_in_user()
        key = db.Key.from_path('Comments', int(comment_id))
        comment = db.get(key)
        self.comment_exists(comment)
        if self.read_secure_cookie('userid') == comment.commenter:
            self.render('delete_comment.html', comment=comment)
        else:
            self.redirect('/blog/edit-post/error')

    def post(self, comment_id):
        self.logged_in_user()
        comment_id = self.request.get('comment_id')
        comment = self.get_comment_by_id(comment_id)
        self.comment_exists(comment)
        post_id = comment.post
        if self.read_secure_cookie('userid') == comment.commenter:
            if self.request.get('Delete'):
                comment.delete()
                self.redirect('/blog/comment-update/%s' % str(comment.post))
            elif self.request.get('Cancel'):
                self.redirect('/blog/')
        else:
            self.redirect('/blog/edit-post/error')


class CommentEdit(Handler):

    def get(self, comment_id):
        self.logged_in_user()
        key = db.Key.from_path('Comments', int(comment_id))
        comment = db.get(key)
        self.comment_exists(comment)
        if self.read_secure_cookie('userid') == comment.commenter:
            self.render('edit_comment.html', comment=comment)
        else:
            self.redirect('/blog/edit-post/error')

    def post(self, comment_id):
        self.logged_in_user()
        comment_id = self.request.get('comment_id')
        comment_content = self.request.get('edited_comment')
        comment = self.get_comment_by_id(comment_id)
        self.comment_exists(comment)
        if self.read_secure_cookie('userid') == comment.commenter:
            comment.comment = comment_content
            comment.put()
            self.redirect('/blog/comment-update/%s' % str(comment.post))
        else:
            self.redirect('/blog/edit-post/error')


class ErrorPage(Handler):

    def get(self):
        self.render('error_page.html')


class LikeError(Handler):

    def get(self):
        self.render('like_error.html')


class StatusUpdate(Handler):

    def get(self):
        self.render('updated.html')


class CommentUpdate(Handler):

    def get(self, post):
        self.render('comment_updated.html', post_id=post)


class LikeRemoved(Handler):

    def get(self):
        self.render('like_removed.html')


class LikeAdded(Handler):

    def get(self):
        self.render('like_added.html')


app = webapp2.WSGIApplication([('/blog/?', MainPage),
                               ('/', MainPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/signup', Signup),
                               ('/blog/welcome', Welcome),
                               ('/blog/login', Login),
                               ('/blog/logout', Logout),
                               ('/blog/edit-post/([0-9]+)', EditPost),
                               ('/blog/edit-post/error', ErrorPage),
                               ('/blog/delete-post/([0-9]+)', DeletePost),
                               ('/blog/delete-post/error', ErrorPage),
                               ('/blog/post-update', StatusUpdate),
                               ('/blog/comment-update/([0-9]+)', CommentUpdate),
                               ('/blog/comment-edit/([0-9]+)', CommentEdit),
                               ('/blog/comment-delete/([0-9]+)', CommentDelete),
                               ('/blog/like-post/error', LikeError),
                               ('/blog/like-status-removed', LikeRemoved),
                               ('/blog/like-status-added', LikeAdded),
                               ],
                              debug=True)
