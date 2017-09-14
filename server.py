from flask import Flask, request, redirect, render_template, session, flash
import re
import pprint
from mysqlconnection import MySQLConnector
import md5
import os, binascii 
salt = binascii.b2a_hex(os.urandom(15))

app = Flask(__name__)
mysql = MySQLConnector(app,'login')
app.secret_key = "2145sdsd54s5d45sd"

@app.route('/')
def index():
    if 'id' in session:    
        return render_template('index.html')
    else:
        session['id'] = ''
        return render_template('index.html')

@app.route('/success')
def display():
    query = "SELECT * FROM users WHERE id = :id"
    data = {'id':session['id'],}
    the_user = mysql.query_db(query,data)
    
    return render_template('success.html', the_user = the_user)

####################################
@app.route('/login', methods=['POST'])
def for_login():
    login_email =  request.form['login_email']
    login_pw = request.form['login_pw']
    email_regex = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
    email_found = False

    if len(login_email) < 1:
        flash(u"Your email cannot be empty!","error")
    else:
        if not email_regex.match(login_email):
            flash(u"Login email is not valid!","error")
        else:            
            query = "SELECT id, email FROM users"
            users_info = mysql.query_db(query)            
            for n in users_info:
                if login_email == n['email']:
                    email_found = True
                    session['id'] = n['id']

    if email_found:
        if len(login_pw) < 1:
            flash(u'Your password cannot be empty!','error')
        else:
            query = "SELECT password, salt FROM users WHERE id = :id"
            query_data = {'id': session['id'],}
            users_info = mysql.query_db(query,query_data)
            encrypted_pw = md5.new(login_pw + users_info[0]['salt']).hexdigest()
            if encrypted_pw == users_info[0]['password']:
                return redirect('/success')
            else:
                flash(u'Your password is incorrect!','error')
                
    return redirect('/')        


################################################################
@app.route('/registration', methods=['POST'])
def register_it():
    first_name = request.form['first_name']
    last_name = request.form['last_name']    
    email = request.form['email']
    password = request.form['password']
    confir_pw = request.form['confir_pw']

    # input validation
    name_regex = re.compile(r'^[A-Z][a-z]+$')
    email_regex = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
    pw_regex = re.compile(r'^[a-zA-Z0-9.+_-]{8,}$')
    count = 0
    # validate first name
    if len(first_name) < 1:
        flash(u"Your first name cannot be empty!","error")
    else:
        if len(first_name) < 2:
            flash(u"Name should have at least 2 characters","error")
        else:
            if not name_regex.match(first_name):
                flash(u"Incorrect name format","error")
            else:
                count += 1
    # validate last name
    if len(last_name) < 1:
        flash(u"Your last name cannot be empty!","error")
    else:
        if len(last_name) < 2:
            flash(u"Name should have at least 2 characters","error")
        else:
            if not name_regex.match(last_name):
                flash(u"Incorrect name format","error")
            else:
                count += 1
                

    # validate email
    if len(email) < 1:
        flash(u"Your email cannot be empty!","error")
    else:
        if not email_regex.match(email):
            flash(u"Email is not valid!","error")
        else:            
            query = "SELECT email FROM users"
            users_email = mysql.query_db(query)
            found_email = False
            for n in users_email:
                if email == n['email']:
                    found_email = True
                    flash(u"Email has been registered, please use other emails!","error")
            if not found_email:
                count += 1

    # validate password
    if len(password) < 1:
        flash(u"Your password cannot be empty!","error")
    else:
        if not pw_regex.match(password):
            flash(u"Password should have at least 8 characters!","error")
        else:
            count += 1

    # validate confir_pw
    if password != confir_pw:
        flash(u"Password confirmation do not match!","error")
    else:
        count += 1


    # save input to database

    if(count == 5):
        salt = binascii.b2a_hex(os.urandom(15))
        hashed_pw = md5.new(password + salt).hexdigest()
                
        query = "INSERT INTO users (first_name,last_name,email,password,salt, created_at,updated_at) \
                 VALUES (:first_name,:last_name,:email,:password,:salt,NOW(),NOW())"           
                
        data = {
                'first_name':first_name,
                'last_name':last_name,
                'email': email,
                'password':hashed_pw,
                'salt':salt,
            }
                
        mysql.query_db(query, data)

        new_user = mysql.query_db("SELECT MAX(id) as id FROM users")
        session['id'] = new_user[0]['id']
        return redirect('/success')

    return redirect('/')


app.run(debug=True)
