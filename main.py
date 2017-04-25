import os  # operating system operations
import time  # We need clock, don't we?
import webapp2  # google app framework, I think
import jinja2  # html templating
import re  # reg expression
import hmac  # hasher with additional
import random  # generate pseduo-random data
import hashlib  # needed something with the salt
from string import letters  # ABC's
# from google.appengine.ext import db # datastore for storing data
from models import *

# establishing the standard directory for jinja templating

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def salty_password(name, password, salt=None):
    """
    We like salty food, but the bad guys don't like salty passwords
    so we add the salt to our password just like we do with our jerky,
    by using unique name, unique salt, and presumely unquie password,
    and mix it up with nice sha256 hasher
    """
    if not salt:
        salt = ''.join(random.choice(letters)for z in xrange(5))
    salting = hashlib.sha256(name+password+salt).hexdigest()
    return '%s|%s' % (salt, salting)


# Making sure the hash browns are properly salted...
def tasting_salt(name, password, hashedpassword):
    """
    This function tests whether the password and username is properly salted.
    In other words, this fxn is used to verify the password as we do not store
    the actual passwords, but the hashes themselves, so we have to recreate the
    salted hashes when the user login with their password.
    """
    taste = hashedpassword.split('|')[0]
    return salty_password(name, password, taste) == hashedpassword


def hmac_str(s):
    Secret_Hmac = 'JustPassword'  # Yes, this is a bad practice.
    return '%s|%s' % (s, hmac.new(Secret_Hmac, s).hexdigest())


def user_check(self, *args, **kwargs):
    user = self.request.cookies.get('username')
    if user:
        username = user.split('|')[0]
        if user == hmac_str(username):
            return username
    else:
        return False


def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return USER_RE.match(username)


def valid_email(email):
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
    return EMAIL_RE.match(email) or not email


def valid_password(password):
    PASS_RE = re.compile(r"^.{3,20}$")
    return PASS_RE.match(password)


class Handler(webapp2.RequestHandler):
    """
    Designed to handle low level operations for writing,
    rendering and simplifying the process of creating
    readable website using templates and transistions.
    """

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class MainPage(Handler):
    """
    A main page which is designed to handle all of the website relating
    to the blogging, control the access, and show specific properities
    according to each permissions
    """

    def get(self):
        message = self.request.get('message')
        username = user_check(self)
        if username:
            blogs = Blog.all()
            blog_comments = Comments.all()
            self.render("base.html", user=username, blogs=blogs,
                        blog_comments=blog_comments, message=message)
        if not username:
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
    """
    Class Login is to handle all the login procedure for users
    processing by checking the username and the password against the
    database we have
    """

    def get(self):
        self.redirect('/')

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        q = User.all().filter('user_name =', username)
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
    """
    This class is designed to handle both basic logout
    and error handling in relation to cookie corruption to
    which it resets to nothing and return to login page.
    """
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.headers.add_header(
                                        'Set-Cookie',
                                        'username =; Path=/')
        self.redirect('/')


class NewPost(Handler):
    """ A class to handle creation of a new post on blog """
    def get(self):
        # user = self.request.cookies.get('username')
        # username = user.split('|')[0]
        username = user_check(self)
        if username:
            self.render('newpost.html', user=username)
        if not username:
            self.redirect('/logout')

    def post(self):
        # user = self.request.cookies.get('username')
        # username = user.split('|')[0]
        username = user_check(self)
        if username:
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
        else:
            self.redirect('/logout')

class PostPost(Handler):
    def get(self, blog_id):
        # user = self.request.cookies.get('username')
        # username = user.split('|')[0]
        username = user_check(self)
        if username:
            key = db.Key.from_path('Blog', int(blog_id))
            blog = db.get(key)

            if not blog:
                self.error(404)
                return

            self.render("permalink.html", blog=blog, user=username)
        else:
            self.redirect('/logout')


class DeletePost(Handler):
    def get(self, blog_id):
        username = user_check(self)
        if username:
            thispost = Blog.get_by_id(int(blog_id))
            if thispost is not None:
                if thispost.owner == username:
                    thispost.delete()
                    time.sleep(0.1)
                    self.redirect('/?message= Successful Deletion!')
                else:
                    self.redirect('/')
        else:
            self.redirect('/logout')


class EditPost(Handler):
    def get(self, blog_id):
        username = user_check(self)
        if username:
            thispost = Blog.get_by_id(int(blog_id))
            if thispost is not None:
                if thispost.owner == username:
                    self.render('editpost.html', post=thispost, user=username)
                else:
                    self.redirect('/')
        else:
            self.redirect('/logout')

    def post(self, blog_id):
        username = user_check(self)
        if username:
            subject = self.request.get("subject")
            content = self.request.get("content")
            thispost = Blog.get_by_id(int(blog_id))
            if thispost is not None:   # just making sure it exists
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
            else:
                self.redirect('/')
        else:
            self.redirect('/logout')


class LikePost(Handler):
    def get(self, blog_id):
        username = user_check(self)
        if username:
            thispost = Blog.get_by_id(int(blog_id))
            if thispost is not None:
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
        else:
            self.redirect('/logout')

class CommentPost(Handler):
    def get(self, blog_id):
        username = user_check(self)
        if username:
            self.render('comment.html', user=username)
        else:
            self.redirect('/logout')

    def post(self, blog_id):
        # user = self.request.cookies.get('username')
        # username = user.split('|')[0]
        username = user_check(self)
        if username:
            content = self.request.get("content")

            if content:
                comment = Comments(comment=content, owner=username,
                                   blogID=int(blog_id))
                comment.put()
                time.sleep(0.1)
                self.redirect('/')

            else:
                error = 'The content is required for submission'
                self.render('comment.html', user=username,
                            error=error)
        else:
            self.redirect('/logout')


class DeleteComment(Handler):
    def get(self, blog_id):
        # user = self.request.cookies.get('username')
        # username = user.split('|')[0]
        username = user_check(self)
        if username:
            thiscomment = Comments.get_by_id(int(blog_id))
            if thiscomment is not None:
                if thiscomment.owner == username:
                    thiscomment.delete()
                    time.sleep(0.1)
                    self.redirect('/?message= Successful Deletion!')
                else:
                    self.redirect('/')
        else:
            self.redirect('/logout')


class EditComment(Handler):
    def get(self, blog_id):
        # user = self.request.cookies.get('username')
        # username = user.split('|')[0]
        username = user_check(self)
        if username:
            thiscomment = Comments.get_by_id(int(blog_id))
            if thiscomment is not None:
                if thiscomment.owner == username:
                    self.render('comment.html', content=thiscomment.comment,
                                user=username)
                else:
                    self.redirect('/')
        else:
            self.redirect('/logout')

    def post(self, blog_id):
        #user = self.request.cookies.get('username')
        #username = user.split('|')[0]
        username = user_check(self)
        if username:
            content = self.request.get("content")
            thiscomment = Comments.get_by_id(int(blog_id))
            if thiscomment is not None:
                if thiscomment.owner == username:
                    if content:
                        thiscomment.comment = content
                        thiscomment.put()
                        time.sleep(0.1)
                        self.redirect('/')
                    else:
                        error = 'The content is required for submission'
                        if thiscomment.owner == username:
                            self.render('comment.html',
                                        error=error, user=username)
                        else:
                            self.redirect('/')
        else:
            self.redirect('/logout')


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
