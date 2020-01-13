import datetime
import re
import redis
import bcrypt
import jwt
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response

app = Flask(__name__)
app.secret_key = 'bvoeqwghfelwhfjoilw'
db = redis.Redis(host='redis', port=6379, decode_responses=True)
db.flushdb()  # uncomment in order to flush the database


@app.route('/login/', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username, password = request.form['username'], request.form['password']
        if username == 'test' and password == 'test':
            msg = 'Authorization OK'
            return render_template('index.html', msg=msg)
        '''
        if bcrypt.checkpw(password.encode('utf8'), db.hget(login, 'password').encode('utf8')):
            token = jwt.encode({'user': username,
                                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=50)},
                               app.config['SECRET_KEY'])
            return jsonify({'token': token.decode('UTF-8')})
        '''
        msg = 'Authorization failed'
    return render_template('index.html', msg=msg)


@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username, password, email = request.form['username'], request.form['password'], email = request.form['email']

    elif request.method == 'POST':
        msg = 'Please fill out the form!'
    return render_template('register.html', msg=msg)


@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/home')
def home():
    if 'loggedin' in session:
        return render_template('home.html', username=session['username'])
    return redirect(url_for('login'))


@app.route('/profile')
def profile():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['id']])
        account = cursor.fetchone()
        return render_template('profile.html', account=account)
    return redirect(url_for('login'))
