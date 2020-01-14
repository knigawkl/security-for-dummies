import uuid
import redis
import bcrypt
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response

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
        if bcrypt.checkpw(password.encode('utf8'), db.hget(username, 'password').encode('utf8')):
            session['loggedin'] = True
            session['id'] = db.hget(username, 'id')
            session['username'] = db.hget(username, 'username')
            return redirect(url_for('home'))
        else:
            msg = 'Incorrect username/password!'
    return render_template('index.html', msg=msg)


@app.route('/register/', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username, password, email = request.form['username'], request.form['password'], request.form['email']
        if username and db.hget(username, 'username') == username:
            msg = 'Login unavailable'
            return render_template('register.html', msg=msg)
        else:
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password.encode('utf8'), salt)
            hashed = hashed.decode("utf-8")

            db.hset(username, 'username', username)
            db.hset(username, 'password', hashed)
            db.hset(username, 'email', email)
            db.hset(username, 'id', str(uuid.uuid1()))

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


@app.route('/home/')
def home():
    if 'loggedin' in session:
        return render_template('home.html', username=session['username'])
    return redirect(url_for('login'))


@app.route('/profile/')
def profile():
    if 'loggedin' in session:
        username = session['username']
        email = db.hget(username, 'email')
        account = {'username': username, 'email': email}
        return render_template('profile.html', account=account)
    return redirect(url_for('login'))
