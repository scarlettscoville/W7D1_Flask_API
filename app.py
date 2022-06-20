from flask import Flask, make_response, request, g, abort
import os
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps


class Config():
    SQLALCHEMY_DATABASE_URI = os.environ.get("SQLALCHEMY_DATABASE_URI")
    SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get("SQLALCHEMY_TRACK_MODIFICATIONS")

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy()
migrate = Migrate(app, db)
basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth()
db.init_app(app)

def require_admin(f, *args, **kwargs):
    @wraps(f)
    def check_admin(*args, **kwargs):
        if not g. current_user.is_admin:
            abort(403)
        else:
            return f(*args, **kwargs)
    return check_admin

@basic_auth.verify_password
def verify_password(email, password):
    u = User.query.filter_by(email=email).first()
    if u is None:
        return False
    g.current_user = u
    return u.check_hashed_password(password)

@token_auth.verify_token
def verify_token(token):
    u = User.check_token(token) if token else None
    g.current_user = u
    return u

class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, index=True, unique=True)
    password = db.Column(db.String)
    reading_list = db.relationship("Book", backref="author", lazy="dynamic", cascade='all, delete-orphan')

    def hash_password(self, original_password):
        return generate_password_hash(original_password)

    def check_hashed_password(self, login_password):
        return check_password_hash(self.password, login_password)

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def __repr__(self):
        return f'<{self.user_id} | {self.email}>'

    def from_dict(self, data):
        self.email = data['email']
        self.password = self.hash_password(data['password'])

    def to_dict(self):
        return {"user_id": self.user_id, "email": self.email}

class Book(db.Model):
    book_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String)
    author = db.Column(db.String)
    pages = db.Column(db.Integer)
    summary = db.Column(db.Text)
    img = db.Column(db.String)
    subject = db.Column(db.String)
    user_id = db.Column(db.ForeignKey('user.user_id'))

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def __repr__(self):
        return f'<{self.book_id} | {self.title}>'

    def from_dict(self, data):
        self.title = data['title']
        self.author = data['author']
        self.pages = data['pages']
        self.summary = data['summary']
        self.img = data['img']
        self.subject = data['subject']
        self.user_id = data ['user_id']

    def to_dict(self):
        return {"user_id":self.user_id,
                "title":self.title,
                "author":self.author,
                "pages":self.pages,
                "summary":self.summary,
                "img":self.img,
                "subject":self.subject,
                "book_id":self.book_id
                }

@app.get('/login')
@basic_auth.login_required()
def login():
    return make_response(f'login successful for user id: {g.current_user.user_id}', 200)

@app.get('/user')
def get_users():
    return make_response({
        "users":[user.to_dict() for user in User.query.all()]}, 200)

@app.get('/user/<int:user_id>')
def get_user(user_id):
    return make_response(User.query.get(user_id).to_dict(), 200)

@app.post('/user')
def post_user():
    data = request.get_json()
    new_user = User()
    new_user.from_dict(data)
    new_user.save()
    return make_response("success", 200)

@app.put('/user/<int:user_id>')
def put_user(user_id):
    data = request.get_json()
    user = User.query.get(user_id)
    user.from_dict(data)
    user.save()
    return make_response("success", 200)

@app.delete('/user/<int:user_id>')
def delete_user(user_id):
    User.query.get(user_id).delete()
    return make_response("success", 200)

@app.get('/book')
def get_books():
    return make_response({"books":[book.to_dict() for book in Book.query.all()]}, 200)

@app.get('/book/<int:book_id>')
def get_book(book_id):
    return make_response(Book.query.get(book_id).to_dict(), 200)

@app.post('/book')
def post_book():
    data = request.get_json()
    new_book = Book()
    new_book.from_dict(data)
    new_book.safe()
    return make_response("success", 200)

@app.put('/book/<int:book_id>')
@token_auth.login_required()
@require_admin
def put_book(book_id):
    data = request.get_json()
    book = Book.query.get(book_id)
    book.from_dict(data)
    book.save()
    return make_response("success", 200)

@app.delete('/book/<int:book_id>')
@token_auth.login_required()
@require_admin
def delete_book(book_id):
    Book.query.get(book_id).delete()
    return make_response("success", 200)

@app.get('/book/user/<int:user_id>')
def get_book_by_user_id(user_id):
    return make_response({"books":[book.to_dict() for book in User.query.get(user_id).books]}, 200)