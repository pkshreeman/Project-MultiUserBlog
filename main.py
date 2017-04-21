import os  # operating system operations
import time  # We need clock, don't we?
import webapp2  # google app framework, I think
import jinja2  # html templating
import re  # reg expression
import hmac  # hasher with additional
import random  # generate pseduo-random data
import hashlib  # needed something with the salt
from string import letters  # ABC's
from google.appengine.ext import db

# establishing the standard directory for jinja templating

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)
# regular expression checker for valid entries
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
PASS_RE = re.compile(r"^.{3,20}$")
Secret_Hmac = 'JustPassword'


def salty_password(name, password, salt=None):
    if not salt:
        salt = ''.join(random.choice(letters)for z in xrange(5))
    salting = hashlib.sha256(name+password+salt).hexdigest()
    return '%s|%s' % (salt, salting)


# Making sure the hash browns are properly salted...
def tasting_salt(name, password, hashedpassword):
    taste = hashedpassword.split('|')[0]
    return salty_password(name, password, taste) == hashedpassword


# database for users
class User(db.Model):
    user_name = db.StringProperty(required=True)
    user_hashed_password = db.StringProperty(required=True)
    user_email = db.StringProperty()


# The Blog! database
class Blog(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    owner = db.StringProperty(required=True)
    likedby = db.ListProperty(str, default=[])
    comments = db.TextProperty()
    likes = db.IntegerProperty()


class Comments(db.Model):
    comment = db.TextProperty(required=True)
    owner = db.StringProperty(required=True)
    blogID = db.IntegerProperty(required=True)


def user_query(user):
    # return db.GqlQuery("Select * From User where user_name = '%s'" % user)
    users = User.all()
    return users.filter('user_name =', user)


def hmac_str(s):
    return '%s|%s' % (s, hmac.new(Secret_Hmac, s).hexdigest())


def check_hmac(s):
    val = s.split('|')[0]
    if s == hmac_str(val):
        return val


def valid_username(username):
    return USER_RE.match(username)


def valid_email(email):
    return EMAIL_RE.match(email) or not email


def valid_password(password):
    return PASS_RE.match(password)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class MainPage(Handler):

    def get(self):
        user = self.request.cookies.get('username')
        if user:
            username = user.split('|')[0]
            blogs = Blog.all()
            blog_comments = Comments.all()
            self.render("base.html", user=username, blogs=blogs,
                        blog_comments=blog_comments)
        if not user:
            self.render("base.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        errorQ = False
        params = dict(username=username,
                      email=email)

        if not valid_username(username):
            params['error_name'] = "Invalid Entry"
            errorQ = True

        if not valid_password(password):
            params['error_password'] = "Invalid Password"
            errorQ = True
        elif password != verify:
            params['error_verify'] = "Your password does not match"
            errorQ = True
        if not valid_email(email):
            params['error_email'] = "Invalid email"
            errorQ = True

        if errorQ:
            self.render("register.html", **params)
        elif User.all().filter('user_name =', username).get():
            if str(User.all().filter('user_name =', username).get().user_name) == username: # noqa
                self.render("register.html",
                            error_name="This username already exists")
        else:
            # Putting new user data into store
            adduser = User(user_name=username,
                           user_hashed_password=salty_password(username,
                                                               password),
                           user_email=email)
            adduser.put()
            hashedusername = hmac_str(username)
            self.response.headers['Content-Type'] = 'text/plain'
            self.response.headers.add_header(
                                            'Set-Cookie',
                                            'username = %s; Path=/'
                                            % str(hashedusername))
            self.redirect('/')  # using a cookie instead of http query


class Login(MainPage):

    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")

        q = user_query(username)
        if q.get():
            if q.get().user_name == username:
                hashedpassword = User.all().filter('user_name =', username).get().user_hashed_password  # noqa
                if tasting_salt(username, password, hashedpassword):
                    hashedusername = hmac_str(username)
                    self.response.headers['Content-Type'] = 'text/plain'
                    self.response.headers.add_header(
                                                'Set-Cookie',
                                                'username = %s; Path=/'
                                                % str(hashedusername))
                    self.redirect('/')
                else:
                    self.render("base.html", error="INVALID LOGIN")

        else:
            self.render("base.html", error="INVALID LOGIN")


class Logout(Handler):
    def get(self):
        user = self.request.cookies.get('username')
        if not user:
            self.redirect('/')
        else:
            self.response.headers['Content-Type'] = 'text/plain'
            self.response.headers.add_header(
                                        'Set-Cookie',
                                        'username =; Path=/')
            self.redirect('/')


class NewPost(Handler):
    def get(self):
        user = self.request.cookies.get('username')
        username = user.split('|')[0]
        self.render('newpost.html', user=username)

    def post(self):
        user = self.request.cookies.get('username')
        username = user.split('|')[0]
        subject = self.request.get("subject")
        content = self.request.get("content")
        if content and subject:
            blog = Blog(subject=subject, content=content, owner=username)
            blog.put()
            self.redirect('/%s' % str(blog.key().id()))
        else:
            error = 'The subject and content is required for submission'
            self.render('newpost.html', subject=subject, content=content,
                        error=error)


class PostPost(Handler):
    def get(self, blog_id):
        user = self.request.cookies.get('username')
        username = user.split('|')[0]
        key = db.Key.from_path('Blog', int(blog_id))
        blog = db.get(key)

        if not blog:
            self.error(404)
            return

        self.render("permalink.html", blog=blog, user=username)


class DeletePost(Handler):
    def get(self, blog_id):
        user = self.request.cookies.get('username')
        username = user.split('|')[0]
        key = db.Key.from_path('Blog', int(blog_id))
        blog = db.get(key)

        if not blog:
            self.error(404)
            return

        thispost = Blog.get_by_id(int(blog_id))
        if thispost.owner == username:
            thispost.delete()
            self.write('success!')
        else:
            self.redirect('/')


class EditPost(Handler):
    def get(self, blog_id):
        user = self.request.cookies.get('username')
        username = user.split('|')[0]
        thispost = Blog.get_by_id(int(blog_id))
        if thispost.owner == username:
            self.render('editpost.html', post=thispost, user=username)
        else:
            self.redirect('/')

    def post(self, blog_id):
        user = self.request.cookies.get('username')
        username = user.split('|')[0]
        subject = self.request.get("subject")
        content = self.request.get("content")
        thispost = Blog.get_by_id(int(blog_id))

        if content and subject:
            thispost.subject = subject
            thispost.content = content
            thispost.put()
            self.redirect('/%s' % str(thispost.key().id()))
        else:
            error = 'The subject and content is required for submission'
            if thispost.owner == username:
                self.render('editpost.html', post=thispost, user=username,
                            error=error)
            else:
                self.redirect('/')


class LikePost(Handler):
    def get(self, blog_id):
        user = self.request.cookies.get('username')
        username = user.split('|')[0]
        thispost = Blog.get_by_id(int(blog_id))
        if username != thispost.owner:
            if username in thispost.likedby:
                self.redirect('/')
            else:
                thispost.likedby.append(username)
                if thispost.likes:
                    thispost.likes += 1
                else:
                    thispost.likes = 1
                thispost.put()
                time.sleep(0.1)
                self.redirect('/')
        else:
            self.redirect('/')


class CommentPost(Handler):
    def get(self, blog_id):
        # user = self.request.cookies.get('username')
        # username = user.split('|')[0]
        self.render('comment.html')

    def post(self, blog_id):
        user = self.request.cookies.get('username')
        username = user.split('|')[0]
        content = self.request.get("content")

        if content:
            comment = Comments(comment=content, owner=username,
                               blogID=int(blog_id))
            comment.put()
            time.sleep(0.1)
            self.redirect('/')

        else:
            error = 'The content is required for submission'
            self.render('comment.html',
                        error=error)


class DeleteComment(Handler):
    def get(self, blog_id):
        user = self.request.cookies.get('username')
        username = user.split('|')[0]
        thispost = Comments.get_by_id(int(blog_id))
        if thispost.owner == username:
            thispost.delete()
            self.write('success!')
        else:
            self.redirect('/')


class EditComment(Handler):
    def get(self, blog_id):
        user = self.request.cookies.get('username')
        username = user.split('|')[0]
        thispost = Comments.get_by_id(int(blog_id))
        if thispost.owner == username:
            self.render('comment.html', content=thispost.comment,
                        user=username)
        else:
            self.redirect('/')

    def post(self, blog_id):
        user = self.request.cookies.get('username')
        username = user.split('|')[0]
        content = self.request.get("content")
        thiscomment = Comments.get_by_id(int(blog_id))

        if content:
            thiscomment.comment = content
            thiscomment.put()
            time.sleep(0.1)
            self.redirect('/')
        else:
            error = 'The content is required for submission'
            if thiscomment.owner == username:
                self.render('comment.html',
                            error=error)
            else:
                self.redirect('/')


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/newpost', NewPost),
                               ('/([0-9]+)', PostPost),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/comment/([0-9]+)', CommentPost),
                               ('/like/([0-9]+)', LikePost),
                               ('/delete/([0-9]+)', DeletePost),
                               ('/deletecomment/([0-9]+)', DeleteComment),
                               ('/edit/([0-9]+)', EditPost),
                               ('/editcomment/([0-9]+)', EditComment),
                               ],
                              debug=True)
