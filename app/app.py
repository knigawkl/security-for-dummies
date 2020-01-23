import math
import re
import string
import uuid
import redis
import bcrypt
import time
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response
from password_strength import PasswordPolicy

app = Flask(__name__)
app.secret_key = 'bvoeqwghfelwhfjoilw'
db = redis.Redis(host='redis', port=6379, decode_responses=True)
db.flushdb()  # uncomment in order to flush the database


@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login/', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username, password = request.form['username'], request.form['password']
        if username and not db.exists(username):
            msg = 'Login does not exist'
            return render_template('index.html', msg=msg)
        if bcrypt.checkpw(password.encode('utf8'), db.hget(username, 'password').encode('utf8')):
            session['loggedin'] = True
            session['id'] = db.hget(username, 'id')
            session['username'] = db.hget(username, 'username')
            return redirect(url_for('home'))
        else:
            time.sleep(3)
            msg = 'Incorrect username/password!'
    return render_template('index.html', msg=msg)


policy = PasswordPolicy.from_names(
    length=8,  # min length: 8
    uppercase=1,  # need min. 2 uppercase letters
    numbers=2,  # need min. 2 digits
    special=2,  # need min. 2 special characters
)


def calc_entropy(password):
    return len(password) * (math.log(len(string.ascii_lowercase), 2))


@app.route('/register/', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form \
            and 'password' in request.form and 'repassword' in request.form and 'email' in request.form:
        username, password, email = request.form['username'], request.form['password'], request.form['email']
        repassword = request.form['repassword']
        if not re.match('^[a-zA-Z0-9_]{3,15}$', username):
            msg = f'Login can contain only letters (lowercase/uppercase) and digits and its length must be 3-15 signs'
            return render_template('register.html', msg=msg)
        if password != repassword:
            msg = f'Passwords do not match'
            return render_template('register.html', msg=msg)
        if len(policy.test(password)) > 0:
            msg = f'Password too weak, it has to meet the unmet minimum requirements: {policy.test(password)}'
            entropy = calc_entropy(password)
            msg += f' Current password entropy: {"%.2f" % entropy}'
            return render_template('register.html', msg=msg)
        if calc_entropy(password) < 40:
            entropy = calc_entropy(password)
            msg = f' Current password entropy: {"%.2f" % entropy}.'
            msg += f'Minimum: 40'
            return render_template('register.html', msg=msg)
        if username and db.hget(username, 'username') == username:
            msg = 'Login unavailable'
            return render_template('register.html', msg=msg)
        else:
            salt = bcrypt.gensalt(15)  # the actual number of hashing rounds is math.pow(2, rounds)
            hashed = bcrypt.hashpw(password.encode('utf8'), salt)
            hashed = hashed.decode("utf-8")

            id = str(uuid.uuid1())
            db.hset(username, 'username', username)
            db.hset(username, 'password', hashed)
            db.hset(username, 'email', email)
            db.hset(username, 'id', id)
            db.sadd('users', username)

            msg = 'Account created, please log in'
            return render_template('index.html', msg=msg)
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
    return render_template('register.html', msg=msg)


@app.route('/logout/')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/home/', methods=['GET', 'POST'])
def home():
    msg = ''
    notes = get_notes()
    if 'loggedin' in session:
        if request.method == 'POST' and 'note' in request.form and 'receivers' in request.form:
            note, receivers = request.form['note'], request.form['receivers']
            if receivers != '*':
                try:
                    receivers = receivers.split(',')
                except:
                    msg = "Invalid receivers' usernames"
                    return render_template('home.html', username=session['username'], notes=notes, msg=msg)

                if len(receivers) > 10:
                    msg = "Too many receivers. Up to 10 or everyone (*)!"
                    return render_template('home.html', username=session['username'], notes=notes, msg=msg)

                receivers = set(receivers)
                users = db.smembers('users')
                if not receivers.issubset(users):
                    msg = "Invalid receivers' usernames"
                    return render_template('home.html', username=session['username'], notes=notes, msg=msg)

                receivers = ','.join(map(str, receivers))

            id = str(uuid.uuid1())
            db.hset(id, 'id', id)
            db.hset(id, 'note', note)
            db.hset(id, 'receivers', receivers)
            db.hset(id, 'author', session['username'])
            db.sadd('notes', id)
            notes = get_notes()
            return render_template('home.html', username=session['username'], notes=notes, msg=msg)
        notes = get_notes()
        return render_template('home.html', username=session['username'], notes=notes, msg=msg)
    return redirect(url_for('login'))


def get_notes():
    notes = []
    user = session['username']
    db_resp = db.smembers('notes')
    for id in db_resp:
        receivers = db.hget(id, 'receivers')
        if receivers == '*':
            notes.append(db.hget(id, 'note'))
        else:
            receivers = receivers.split(',')
            if user in receivers:
                #notes.append(db.hget(id, 'note'))
                notes.append({'note': db.hget(id, 'note'), 'author': db.hget(id, 'author')})
    return notes


@app.route('/profile/')
def profile():
    if 'loggedin' in session:
        username = session['username']
        email = db.hget(username, 'email')
        account = {'username': username, 'email': email}
        return render_template('profile.html', account=account)
    return redirect(url_for('login'))


@app.route('/password/', methods=['GET', 'POST'])
def password():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'oldpassword' in request.form \
            and 'password' in request.form and 'repassword' in request.form:
        username, password = request.form['username'], request.form['password']
        oldpassword, repassword = request.form['oldpassword'], request.form['repassword']
        if username and not db.exists(username):
            msg = 'Login does not exist'
            return render_template('password.html', msg=msg)
        if bcrypt.checkpw(oldpassword.encode('utf8'), db.hget(username, 'password').encode('utf8')):
            if password != repassword:
                msg = f'Passwords do not match'
                return render_template('password.html', msg=msg)
            if len(policy.test(password)) > 0:
                msg = f'Password too weak, it has to meet the unmet minimum requirements: {policy.test(password)}'
                entropy = calc_entropy(password)
                msg += f' Current password entropy: {"%.2f" % entropy}'
                return render_template('password.html', msg=msg)
            if calc_entropy(password) < 40:
                entropy = calc_entropy(password)
                msg = f' Current password entropy: {"%.2f" % entropy}.'
                msg += f'Minimum: 40'
                return render_template('password.html', msg=msg)
            else:
                salt = bcrypt.gensalt(15)  # the actual number of hashing rounds is math.pow(2, rounds)
                hashed = bcrypt.hashpw(password.encode('utf8'), salt)
                hashed = hashed.decode("utf-8")

                db.hset(username, 'password', hashed)

                msg = 'Password has been changed'
                return render_template('index.html', msg=msg)
        else:
            time.sleep(3)
            msg = 'Incorrect old password'
    return render_template('password.html', msg=msg)
