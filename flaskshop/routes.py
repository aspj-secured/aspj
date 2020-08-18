import os
import secrets
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort, session, Blueprint
from flaskshop import app, db, bcrypt, mail
from flaskshop.forms import (RegistrationForm, LoginForm, UpdateAccountForm,
                             PostForm, RequestResetForm, ResetPasswordForm, ProductForm, CheckoutForm, ContactUsForm)
from flaskshop.models import User, Post, Product, Cart, ContactUs, Order,  MyAdminIndexView, MyModelView, Timeout
from flask_login import login_user, current_user, logout_user, login_required, LoginManager
from flask_mail import Message

from sqlalchemy import create_engine
from flask import request, jsonify, make_response
#
import sqlite3
from datetime import datetime, timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from email.utils import parseaddr
import logging
limiter = Limiter(app, key_func=get_remote_address, default_limits=['1200 per day', '200 per minute'])
logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S',
                     filename='access.log', level=logging.INFO)

# edison edit x-frame
@app.after_request
def apply_caching(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response


# auto logout after 30min
@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=1)
    session.modified = True


# Jing quan: X-XSS Header set to 1 to prevent XSS from happening
@app.after_request
def noxss(response):
    response.headers["X-XSS-Protection"] = '1; mode=block'
    return response


# Thomas: added secure headers
@app.after_request
def secure_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'none'; script-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js https://code.jquery.com/jquery-3.2.1.slim.min.js; connect-src 'self'; img-src 'self'; style-src 'self' https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    # print(session)
    return response


# Keith: Single Line mode in sqlite3
@app.route('/json', methods=['POST'])
def myjson():
    if request.is_json:
        req = request.get_json().get('message')
        if not req or len(req) != 4:
            print('[JSON] Error 0a - "Invalid field"')
            return redirect(url_for('logout'))
        if len(str(req)) > 75:
            print('[JSON] Error 0 - "req too long": ("%i")' % (len(str(req))))
            return redirect(url_for('logout'))
        iEmail, iCheckval, iLocation = parseaddr(req[0])[1], req[2], req[3]
        sql3db = sqlite3.connect('flaskshop/site.db')
        c = sql3db.cursor()

        # [1] Check if page is from site
        checkpage = ['forum', 'contact us', 'home', 'shop', 'register', 'login', 'account', 'new post', 'view post', 'update post', 'reset password', 'new product', 'update product', 'view product', 'update product', 'checkout', 'orders', 'cart', 'view user']
        for item in checkpage:
            if iLocation.lower() == item:
                break
            elif item in ['view product', 'view post', 'view user']:
                # Special handling for 'str' + 'id'
                if item in ['view product', 'view post'] and (iLocation.lower()[len(item)+2:]).isnumeric():
                    break
                # Handling of id to check if valid email
                elif '@' in parseaddr(iLocation.lower())[1]:
                    if '.' in parseaddr(iLocation.lower())[1]:
                        break
            elif item == checkpage[-1]:
                print('[JSON] Error 1 - "page location": ("%s" , "%s")' % (iEmail, iLocation))
                return redirect(url_for('logout'))

        # [2] Check legitimacy
        try:
            if req[0] != iEmail:
                # Trigger Fail case (attributeError)
                'a'.a
            s = User.query.filter_by(email=iEmail).first().password
            if len(iCheckval) == 7:
                if iCheckval == s[0]+s[12]+s[24]+s[36]+s[48]+s[50]+s[59]:
                    # Passcase to trigger ValueError to break
                    int('a')
                else:
                    print('[JSON] Error 2b - "Check value": ("%s", "%s" against "%s")' % (iEmail, iCheckval, s[0]+s[12]+s[24]+s[36]+s[48]+s[50]+s[59]))
            else:
                print('[JSON] Error 2a - "Length": ("%s")' % iCheckval)
            return redirect(url_for('logout'))
        except AttributeError:
            print('[JSON] Error 2 - "Invalid email detected": ("%s")' % req[0])
            return redirect(url_for('logout'))
        except KeyError:
            print('[JSON] Error 2c - "No checkval in LocalStorage"')
            return redirect(url_for('logout'))
        except ValueError:
            None

        # [Passed]
        try:
            with sql3db:
                tval = [datetime.now().strftime('%d/%m/%y, %H:%M:%S'), iEmail, iLocation]
                c.execute("INSERT INTO history VALUES (:date, :email, :action)", {'date': tval[0], 'email': tval[1], 'action': tval[2]})
            sql3db.close()
            return make_response(jsonify(), 200)
        except:
            print('[JSON] Error found with information:\n[JSON] -> ("{}", "{}", "{}")'.format(tval[0], tval[1], tval[2]))
            return redirect(url_for('logout'))
    return redirect(url_for('logout'))


@app.route("/forum")
def forum():
    page = request.args.get('page', 1, type=int)
    posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    return render_template('forum.html', title='Forum', posts=posts)


@app.route("/contact/<int:user_id>", methods=['GET', 'POST'])
def contact(user_id):
    user = User.query.get_or_404(user_id)
    title = 'Contact Us - ' + user.email
    if current_user != user:  # Jing Quan: To ensure that current user gets his own feedback form to prevent Broken Access Control
        logging.info('{} tried accessing contact_us page of {} (Potential Broken Access Control Attempt)'.format(current_user.username, user.username)) # Jing Quan:Broken Access control attempt is being logged to access.log
        abort(403)
    form = ContactUsForm()
    if form.validate_on_submit():
        contact = ContactUs(subject=form.subject.data, content=form.content.data, author=user)
        db.session.add(contact)
        db.session.commit()
        flash(' Your feedback has been sent!', 'success')
        return redirect(url_for('shop'))
    return render_template('contactus.html', title=title, form =form, legend='New Feedback', user=user)


@app.route("/")
def home():
    page = request.args.get('page', 1, type=int)
    products = Product.query.order_by(Product.id.desc()).paginate(page=page, per_page=5)
    return render_template('shop.html', products=products)


@app.route("/shop")
def shop():
    page = request.args.get('page', 1, type=int)
    products = Product.query.order_by(Product.id.desc()).paginate(page=page, per_page=5)
    return render_template('shop.html', title="Shop", products=products)


def check_password(data):
    with open('10kbadpw.txt', 'r') as myfile:
        for line in myfile:
            if line.strip() == data:
                return False
            else:
                continue
        if len(data) >= 8:
            i=0
            for char in data:
                if char.isupper():
                    i+=1
                    break
            for char in data:
                if char.islower():
                    i+=1
                    break
            for char in data:
                if char.isdigit():
                    i+=1
                    break
            for char in data:
                if char.isalnum() == False:
                    i+=1
                    break
            if i == 4:
                return True
            return False

# Keith: Secured using sqlalchemy and validators
@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('login'))
    form = RegistrationForm()
    for item in [form.username.data, form.email.data, form.password.data, form.confirm_password.data]:
        for char in ['"', "'", "--", ';', '=']:
            if char in str(item):
                flash('Invalid Characters detected. Please check the fields again.', 'danger')
                return render_template('register.html', title='Register', form=form)
    if form.validate_on_submit():
        # passwordcheck edison
        print(check_password(form.password.data))
        if check_password(form.password.data):
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data, email=form.email.data, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash('Your account has been created! You are now able to log in', 'success')
            return redirect(url_for('login'))
        else:
            flash('Password is too weak, You will need the following requirements, An upper,lowercase,integer and a special character while being at least 8 characters long', 'danger')
    return render_template('register.html', title='Register', form=form)


# Keith: secured using sqlalchemy and validators
@app.route("/login", methods=['GET', 'POST'])
@limiter.limit('200 per day')
def login():
    ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    if current_user.is_authenticated:
        return redirect(url_for('shop'))
    form = LoginForm()
    for item in [form.email.data, form.password.data]:
        for char in ['"', "'", "--", ';', '=']:
            if char in str(item):
                flash('Login Unsuccessful. Please check your email and password', 'danger')
                return render_template('login.html', title='Login', form=form)
    if Timeout.query.filter_by(ip=ip).first() == None:
        print('new entry created')
        new = Timeout(ip=ip, attempts=1)
        db.session.add(new)
        db.session.commit()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if Timeout.query.filter_by(ip=ip).first():
                check=Timeout.query.filter_by(ip=ip).first()
                if check.release > datetime.now():
                    flash('You have been locked out for entering too many wrong passwords', 'danger')
                    return render_template('login.html')
                else:
                    check.attempts = 0
                    db.session.commit()
            login_user(user, remember=form.remember.data)
            perms = 'user'
            if current_user.admin_rights:
                perms = 'admin'
            s = user.password
            return render_template('afterLogin.html', email=form.email.data, role=perms, checkval=s[0] + s[12] + s[24] + s[36] + s[48] + s[50] + s[59])
        else:
            c = Timeout.query.filter_by(ip=ip).first()
            c.attempts += 1
            db.session.commit()
            if c.attempts >= 5:
                if c.release > datetime.now():
                    flash('You have been locked out for entering too many wrong passwords', 'danger')
                    c.attempts = 0
                    db.session.commit()
                    return render_template('login.html')
                c.release = datetime.now() + timedelta(minutes=1)
                db.session.commit()
            print(c.ip,'-', c.attempts, '-', c.release)
        flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('shop'))


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn


@app.route("/account/<int:user_id>", methods=['GET', 'POST'])
@login_required
def account(user_id):
    user = User.query.get_or_404(user_id)
    title = 'Account - ' + user.email
    if current_user != user:  # Jing Quan :To ensure that the current user gets his own form and not others to prevent Broken Access Control
        logging.info('{} tried to access account page of {} (Potential Broken Access Control Attempt)'.format(current_user.username, user.username)) # Jing Quan:Broken Access control attempt is being logged to access.log
        abort(403)
    form = UpdateAccountForm()
    image_file = url_for('static', filename='profile_pics/' + user.image_file)
    for item in [form.username.data, form.email.data]:
        for char in ['"', "'", "--", ';', '=']:
            if char in str(item):
                flash('Invalid characters detected. Please check and try again.', 'danger')
                return render_template('account.html', title=title,
                                       image_file=image_file, form=form, user=user)
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            user.image_file = picture_file
        user.username = form.username.data
        user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account', user_id=user.id))
    elif request.method == 'GET':
        form.username.data = user.username
        form.email.data = user.email
    image_file = url_for('static', filename='profile_pics/' + user.image_file)
    return render_template('account.html', title=title,
                           image_file=image_file, form=form, user=user)


@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('forum'))
    return render_template('create_post.html', title='New Post',
                           form=form, legend='New Post')


@app.route("/post/<int:post_id>")
def post(post_id):
    post = Post.query.get_or_404(post_id)
    title = 'View Post - ' + str(post_id)
    return render_template('post.html', title=title, post=post)


@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    title = 'Update Post - ' + str(post_id)
    if post.author != current_user:  #Jing Quan: To check if the post in forum belongs to the correct user to prevent Broken Access Control
        logging.info('{} tried updating a post belonging to {} (Potential Broken Access Control Attempt)'.format(current_user.username, post.author.username)) # Jing Quan:Broken Access control attempt is being logged to access.log
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash('Your post has been updated!', 'success')
        return redirect(url_for('post', post_id=post.id))
    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
    return render_template('create_post.html', title=title,
                           form=form, legend='Update Post')


@app.route("/post/<int:post_id>/delete", methods=['GET', 'POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:  #Jing Quan: To check if the post in the forum belongs to the correct user to prevent Broken Access Control
        logging.info('{} tried deleting a belonging to {} (Potential Broken Access Control Attempt)'.format(current_user.username, post.author.username)) # Jing Quan:Broken Access control attempt is being logged to access.log
        abort(403)
    db.session.delete(post)
    db.session.commit()

    flash('Your post has been deleted!', 'success')
    return redirect(url_for('forum'))


@app.route("/user/<string:username>")
def user_posts(username):
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    title = 'View User - ' + user.email
    posts = Post.query.filter_by(author=user)\
        .order_by(Post.date_posted.desc())\
        .paginate(page=page, per_page=5)
    return render_template('user_posts.html', posts=posts, user=user, title=title)


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='noreply@demo.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('shop'))
    form = RequestResetForm()
    for char in ['"', "'", "--", ';', '=']:
        if char in str(form.email.data):
            flash('Invalid email detected. Please check and try again.', 'danger')
            return render_template('reset_request.html', title='Reset Password', form=form)
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('shop'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        if check_password(form.password.data):
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user.password = hashed_password
            db.session.commit()
            flash('Your password has been updated! You are now able to log in', 'success')
            return redirect(url_for('login'))
        return render_template('reset_token.html', title='Reset Password', form=form)
    return render_template('reset_token.html', title='Reset Password', form=form)


@app.route("/product/new", methods=['GET', 'POST'])
@login_required
def new_product():
    if current_user.admin_rights is False:   #Jing Quan: To check if the current user has admin rights or not to prevent Broken Access Control
        abort(403)
    form = ProductForm()
    for item in [form.name.data, form.price.data, form.qty.data]:
        for char in ['"', "'", "--", ';', '=']:
            if char in str(item):
                flash('Invalid characters detected. Please check and try again.', 'danger')
                return render_template('create_product.html', title='New Product',
                                       form=form, legend='New Product')

    if form.validate_on_submit():
        product = Product(name=form.name.data, price=form.price.data, qty=form.qty.data)
        db.session.add(product)
        db.session.commit()
        flash('Product has been added!', 'success')
        return redirect(url_for('shop'))
    return render_template('create_product.html', title='New Product',
                           form=form, legend='New Product')


@app.route("/product/<int:product_id>")
def product(product_id):
    product = Product.query.get_or_404(product_id)
    title = 'View Product - ' + str(product_id)
    return render_template('product.html', name=product.name, product=product, title=title)


@app.route("/product/<int:product_id>/update", methods=['GET', 'POST'])
@login_required
def update_product(product_id):
    product = Product.query.get_or_404(product_id)
    title = 'Update Product - ' + str(product_id)
    if current_user.admin_rights is False:  # Jing quan- prevent broken access control by checking if user has admin rights
        abort(403)
    form = ProductForm()
    for item in [form.name.data, form.price.data, form.qty.data]:
        for char in ['"', "'", "--", ';', '=']:
            if char in str(item):
                flash('Invalid characters detected. Please check and try again.', 'danger')
                return render_template('create_product.html', title=title,
                                       form=form, legend='Update Product')
    if form.validate_on_submit():
        product.name = form.name.data
        product.price = form.price.data
        product.qty = form.qty.data
        db.session.commit()
        flash('Product has been updated!', 'success')
        return redirect(url_for('post', post_id=post.id))
    elif request.method == 'GET':
        form.name.data = product.name
        form.price.data = product.price
        form.qty.data = product.qty
    return render_template('create_product.html', title=title,
                           form=form, legend='Update Product')


@app.route("/product/<int:product_id>/delete", methods=['POST'])
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    if current_user.admin_rights is False:  #jing quan - prevent borken access control by checking if user has admin rights
        abort(403)
    db.session.delete(product)
    db.session.commit()
    flash('Your product has been deleted!', 'success')
    return redirect(url_for('shop'))


@app.route("/cart", methods=['GET'])
@login_required
def cart():
    page = request.args.get('page', 1, type=int)
    product = Product.query.order_by(Product.id.desc()).paginate(page=page, per_page=5)
    cart_items = Cart.query.order_by(Cart.id.desc()).paginate(page=page, per_page=5)
    return render_template('cart.html', title="Cart", cart_items=cart_items, product=product)


@app.route("/add_to_cart/<int:product_id>", methods=["GET", "POST"])
@login_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)
    cart = Cart(product_id=product_id, product_name=product.name, qty=1, price=product.price, owner_id=current_user.id)
    exisitng_item = Cart.query.filter_by(owner_id=current_user.id, product_id=product.id).first()
    if exisitng_item is None:
        db.session.add(cart)
        db.session.commit()
    else:
        exisitng_item.qty = exisitng_item.qty + 1
        db.session.commit()
    flash('Product has been added to you shopping cart', 'success')
    return redirect(url_for('cart'))


@app.route("/remove_from_cart/<int:product_id>")
@login_required
def remove_from_cart(product_id):
    product = Product.query.get_or_404(product_id)
    cart = Cart.query.filter_by(owner_id=current_user.id, product_id=product.id).first_or_404()
    db.session.delete(cart)
    db.session.commit()
    return redirect(url_for('cart'))


@app.route("/checkout", methods=['GET','POST'])
@login_required
def checkout():
    qty = []
    price = []
    prod_name = []
    form = CheckoutForm()
    cart = Cart.query.filter_by(owner_id=current_user.id).all()
    for i in cart:
        qty.append(i.qty)
        price.append('%.2f' % i.price)
        prod_name.append(i.product_name)
    prod_name = ','.join(prod_name)
    strprice = ','.join("'{0}'".format(n) for n in price)
    strqty = ','.join("'{0}'".format(n) for n in qty)
    temptotalsum = [int(float(price)) * qty for price, qty in zip(price, qty)]
    if form.validate_on_submit():
        order = Order(address=form.address.data, postal=form.postal.data, cardNumber=form.cardNumber.data,
                      expDate=form.expDate.data, cvv=form.cvv.data, product_name=prod_name,
                      price=strprice, qty=strqty, totalsum=sum(temptotalsum), owner_id=current_user.id)
        for i in cart:
            db.session.delete(i)
        db.session.add(order)
        db.session.commit()
        flash('Your order has been submitted!', 'success')
        return redirect(url_for('orders'))
    return render_template('checkout.html', title='Checkout',
                           form=form, legend='Checkout', cart=cart)


@app.route("/orders", methods=['GET', 'POST'])
@login_required
def orders():
    page = request.args.get('page', 1, type=int)
    order = Order.query.order_by(Order.id.desc()).paginate(page=page, per_page=5)
    return render_template('orders.html', title="Orders", order=order)


errors = Blueprint('errors', __name__)


@errors.app_errorhandler(404)
def error_404(error):
    return render_template('404.html'), 404


@errors.app_errorhandler(403)
def error_403(error):
    return render_template('403.html'), 403


@errors.app_errorhandler(500)
def error_500(error):
    return render_template('500.html'), 500