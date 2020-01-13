from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re


app = Flask(__name__)

app.secret_key = 'your secret key'

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'knigawa'
app.config['MYSQL_DB'] = 'security4dummies'

mysql = MySQL(app)


@app.route('/login/', methods=['GET', 'POST'])
def login():
    return render_template('index.html', msg='')
