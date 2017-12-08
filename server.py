from flask import Flask, render_template, redirect, session, flash, request
from mysqlconnection import MySQLConnector
from passlib.hash import pbkdf2_sha256
import re

app=Flask(__name__)
app.secret_key = "DrowssaP"
mysql = MySQLConnector(app, 'users')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

special_character = "!@#$%&_="

def is_valid(pwd):
    global special_character
    return any(char in special_character for char in pwd)    

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    error = False
    if len(request.form['email']) < 1 or len(request.form['password']) < 1:
        flash(u'Fields cannot be blank', 'login_fail')
        error = True
        return redirect('/')
    query = "SELECT users.id, email, password FROM users WHERE email = :email"
    data = {
        'email': request.form['email']
    }
    check = mysql.query_db(query, data)
    if check:
        test_pass = request.form['password']
        original_pass = check[0]['password']
        if pbkdf2_sha256.verify(test_pass, original_pass):
            session['id'] = check[0]['id']
            return redirect('/logged_in')
        # the var that the query sends back has to be told to look at the 0 variable first
        else:
            flash(u'Username or Password do not match with our records', 'login_fail')
            error = True
            return redirect('/')
    else:
        flash(u'Username or Password do not match with our records', 'login_fail')
        error = True
        return redirect('/')
    if error == True:
        flash(u'Username or Password do not match with our records', 'login_fail')
        return redirect('/')
    else:
        return redirect('/logged_in')
    return redirect('/')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/registering', methods=['POST'])
def registering():
    error = False
    if len(request.form['email']) < 1 or len(request.form['password']) < 1 or len(request.form['first_name']) < 1 or len(request.form['last_name']) < 1 or len(request.form['confirm_password']) < 1:
        flash(u"Please don't leave any fields blank", 'incomplete')
        error = True
        return redirect('/register')
    if not EMAIL_REGEX.match(request.form['email']):
        flash(u'Please enter a valid email', 'invalid_email')
        error = True
        return redirect('/register')
    if request.form['password'] < 1 or is_valid(request.form['password']) == False:
        flash(u'Passwords must contain 8 characters, including 1 uppercase and 1 special character', 'invalid_password')
        error = True
        return redirect('/register')
    checkval = {
        'email': request.form['email']
    }
    check = mysql.query_db('SELECT email FROM users WHERE email = :email', checkval)
    if len(check) > 0:
        flash(u'Email is already registered', 'invalid_email')
        error = True
        return redirect('/register')
    if not request.form['first_name'].isalpha() or not request.form['last_name'].isalpha():
        flash(u'Names must not contain special characters or numbers', 'invalid_name')
        error = True
        return redirect('/register')
    if request.form['password'] != request.form['confirm_password']:
        flash(u'Passwords entered do not match', 'invalid_password')
        error = True
        return redirect('/register')
    if error == True:
        return redirect('/register')
    else:
        hash = pbkdf2_sha256.hash(request.form['password'])
        success_query = "INSERT INTO users (email, password, first_name, last_name, created_at, updated_at) VALUES (:email, :password, :first_name, :last_name, NOW(), NOW())"
        success_data = {
            'email': request.form['email'],
            'password': hash,
            'first_name': request.form['first_name'],
            'last_name': request.form['last_name'],
        }
        id = mysql.query_db(success_query, success_data)
        session['id'] = id
        return redirect('/logged_in')

@app.route('/logged_in')
def logged_in():
    if not session.values():
        return redirect('/')
    # there's gotta be a better way
    # if not session['id']:
    #     return redirect('/')
    email = mysql.query_db('SELECT email FROM users WHERE id=' + str(session['id']))
    name = email[0]['email']
    session['name'] = name.upper()
    return render_template('logged_in.html')

@app.route('/logout')
def log_out():
    del session['name']
    del session['id']
    return redirect ('/')

app.run(debug=True)