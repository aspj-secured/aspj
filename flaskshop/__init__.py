import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from flask_login import LoginManager
import logging


app = Flask(__name__)
app.config['MAIL_USERNAME'] = 'flaskshopaspjhelp@gmail.com'
app.config['MAIL_PASSWORD'] = 'pass108369123'
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
log = logging.getLogger('werkzeug')
log.disabled = True
app.logger.disabled = True


mail = Mail(app)
from flaskshop import routes

from flaskshop.routes import errors
app.register_blueprint(errors)



















































































































