from datetime import datetime
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flaskshop import db, login_manager, app
from flask_login import UserMixin, LoginManager, current_user
from flask_admin.contrib.sqla import ModelView
from flask_admin import Admin, AdminIndexView
from flask import Flask, redirect, url_for
# import sqlite3
# Recreate History Table (SQLITE3 module)
# sql3db = sqlite3.connect('flaskshop/site.db')
# c = sql3db.cursor()
# c.execute("DROP TABLE IF EXISTS history")
# c.execute("""CREATE TABLE history (time text, email text, action text)""")
# sql3db.commit()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)
    cart_details = db.relationship('Cart', backref='owner', lazy=True)
    contact_us = db.relationship('ContactUs', backref='author', lazy=True)
    order_details = db.relationship('Order', backref='owner', lazy=True)
    admin_rights = db.Column(db.Boolean, unique=False, default=False)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"


class MyModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.admin_rights is True #Jing Quan: Admin view is only accessible to users with admin rights
    # This line checks if user is admin to prevent Broken Access Control


class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.admin_rights is True #Jing Quan: Admin view is only accessible to users with admin rights
    # This line checks if user is admin to prevent Broken Access Control


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float(2, 2), nullable=False)
    qty = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f"Product('{self.id}',{self.name},'{self.price}')"


class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    product_name = db.Column(db.String, nullable=False)
    qty = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float(2, 2), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class ContactUs (db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(100), nullable=False)
    postal = db.Column(db.String(100), nullable=False)
    cardNumber = db.Column(db.String(100), nullable=False)
    expDate = db.Column(db.String(100), nullable=False)
    cvv = db.Column(db.String(100), nullable=False)
    product_name = db.Column(db.String, nullable=False)
    qty = db.Column(db.Integer, nullable=False)
    price = db.Column(db.String, nullable=False)
    totalsum = db.Column(db.Float(2, 2), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class Timeout(db.Model):
    ip = db.Column(db.String(100), primary_key=True)
    attempts = db.Column(db.Integer)
    start = db.Column(db.DateTime, nullable=True)
    release = db.Column(db.DateTime, nullable=True)


admin = Admin(app, index_view=MyAdminIndexView(), name="Admin Dashboard")
admin.add_view(MyModelView(User, db.session))
admin.add_view(MyModelView(Post, db.session))
admin.add_view(MyModelView(Product, db.session))
admin.add_view(MyModelView(Cart, db.session))
admin.add_view(MyModelView(ContactUs, db.session, name='Feedback'))
admin.add_view(MyModelView(Order, db.session))


