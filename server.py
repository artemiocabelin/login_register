from flask import Flask, request, redirect, render_template, session, flash
from mysqlconnection import MySQLConnector
import re
import md5
import os,binascii

noNumberPls = re.compile(r'^[a-zA-Z]+$')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
salt = binascii.b2a_hex(os.urandom(15))
app = Flask(__name__)
app.secret_key = 'Secret'
mysql = MySQLConnector(app,'registered_users')

@app.route('/')
def index():
    return  render_template('index.html')

@app.route('/register', methods=["POST"])
def process():
    form = request.form
    errors =[]

    # Checks first_name input
    # start with empty case
    if len(form['first_name']) == 0:
        errors.append('Please enter your first name.')
    # then if it it's less than 2 char
    elif len(form['first_name']) < 2:
        errors.append('First name must be at least 2 characters.')
    # then if it has no numbers in it
    elif not noNumberPls.match(form['first_name']):
        errors.append('First name can only contain letters.')

    # Checks last_name input
    # if empty
    if len(form['last_name']) == 0:
        errors.append('Please enter your last name')
    # then if it's less than 2 characters
    elif len(form['last_name']) < 2:
        errors.append('Last name must be at least two characters.')
    # then if it's has no numbers in it
    elif not noNumberPls.match(form['last_name']):
        errors.append('Last name contain only letters.')

    # Check email input
    # if empty
    if len(form['email']) == 0:
        errors.append('Please enter your email')
    # then if it matches proper email format
    elif not EMAIL_REGEX.match(form['email']):
        errors.append('Please enter a proper email address.')

    # Check Password input
    # if empty
    if len(form['password']) == 0:
        errors.append('Please enter your password.')
    # if it's less than 8 characters
    elif len(form['password']) < 8:
        errors.append('Password must be more than 8 characters.')
    # if password and confirm password dont' match
    elif form['password'] != form['passconf']:
        errors.append('Password and Confirm Password do not match.')
    

    # after building the error list we check the list of errors
    # if not empty flash each errors
    if len(errors) > 0:
        for error in errors:
            flash(error,'errors')
    # if empty then we can now insert the data into the database
    else:
        # but first we check if the email already exists.
        check_email = mysql.query_db("SELECT * FROM users WHERE email = :email", {'email':form['email']})
        if len(check_email) > 0:
            flash('This email already exists.','errors')
        else:
            # if not matched email in the database we finally insert new info into database.
            salt =  binascii.b2a_hex(os.urandom(15))
            hashed_pw = md5.new(form['password'] + salt).hexdigest()
            insert_query = "INSERT INTO `registered_users`.`users` (`first_name`, `last_name`, `email`, `password`, `salt`, `created_at`, `updated_at`) VALUES (:first_name, :last_name, :email, :hashed_pw, :salt, NOW(), NOW());"
            query_data = {
                'first_name': form['first_name'],
                'last_name' : form['last_name'],
                'email'     : form['email'],
                'hashed_pw' : hashed_pw,
                'salt'      : salt
            }
            # actually insert if it fails we will flash an error.
            try:
                user_id = mysql.query_db(insert_query, query_data)
                flash('Successfully registered your account!', 'success')
            except:
                flash('Something went wrong...','errors')

    return redirect('/')

@app.route('/login', methods=['POST'])
def login():
    form = request.form
    # We check if email is in proper format
    if EMAIL_REGEX.match(form['email']):
        # if it does start looking for a match in the database.
        user_query = "SELECT * FROM users WHERE email = :email"
        query_data = {'email': form['email']}
        user = mysql.query_db(user_query, query_data)
        # check if we found one.
        if len(user) > 0:
            # if found we take the given password and check if it matches with the database
            encrypted_password = md5.new(form['password'] + user[0]['salt']).hexdigest()
            if user[0]['password'] == encrypted_password and user[0]['email']==form['email']:
                # we get the user id to start a session.
                session['user_id'] = user[0]['id']
                # we tell the user if it was a success
                flash('Success!')
                # direct to success page
                return redirect('/success')
    return redirect('/')

@app.route('/success')
def success():
    # we check if the user is actually in a session.
    if 'user_id' not in session:
        # if not then we direct user out of the page
        flash('You are not logged in. Goodbye', 'errors')
        return redirect('/')
    # if success we pull out all relevant data for the user.
    current_user = mysql.query_db('SELECT * FROM users WHERE id = :id', {'id': session['user_id']})
    return render_template('/success.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

app.run(debug=True)
