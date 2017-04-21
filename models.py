from google.appengine.ext import db  # datastore for storing data


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
