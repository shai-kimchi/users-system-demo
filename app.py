from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL, MySQLdb
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, Length, InputRequired, Regexp
import bcrypt
import smtplib
import hashlib
import ssl
import json
import random
import string
from MyConfig import *

app = Flask(__name__)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'shai'
app.config['MYSQL_PASSWORD'] = 'orit100!'
app.config['MYSQL_DB'] = 'cyberdb'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql = MySQL(app)

config = MyConfig()

prevent = True

counter = 0

class SignUpForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), InputRequired('A Username is required')])

    email = StringField('Email Address', validators=[DataRequired(), InputRequired('A Email address is required'),
                                                     Email(message="Please enter right email address")])
    password = PasswordField('Password', validators=[DataRequired(), InputRequired('Password is required'),
                                                     Length(min=config.password_lenth,
                                                            message=f'Password must be {config.password_lenth} charecters or more'),
                                                     Regexp(config.password_Regexp[0],
                                                            message=config.password_Regexp[1])])
    submit = SubmitField('Sign up')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), InputRequired('A Username is required')])

    password = PasswordField('Password', validators=[DataRequired(), InputRequired('Password is required'),
                                                     Length(min=config.password_lenth,
                                                            message=f'Password must be {config.password_lenth} charecters or more'),
                                                     Regexp(config.password_Regexp[0],
                                                            message=config.password_Regexp[1])])
    submit = SubmitField('Log in')


class ChangePasswordForm(FlaskForm):
    currPassword = PasswordField('Correct Password',
                                 validators=[DataRequired(), InputRequired('Current Password is required'),
                                             Length(min=config.password_lenth,
                                                    message=f'Password must be {config.password_lenth} charecters or more'),
                                             Regexp(config.password_Regexp[0],
                                                    message=config.password_Regexp[1])])
    newPassword = PasswordField('New Password', validators=[DataRequired(), InputRequired('New Password is required'),
                                                            Length(min=config.password_lenth,
                                                                   message=f'Password must be {config.password_lenth} charecters or more'),
                                                            Regexp(config.password_Regexp[0],
                                                                   message=config.password_Regexp[1])])
    submit = SubmitField('Change password')


@app.route('/')
def home():
    session['client'] = 'yes'
    session.pop('client')
    return render_template("home.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    global counter
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data.encode('utf-8')
        if prevent is False:
            curl = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            curl.execute("SELECT * FROM users WHERE username = %s AND password = %s " % (username, password))
            user = curl.fetchone()
            curl.close()
            session['username'] = user['username']
            return redirect(url_for('home'))
        else:
            if counter >= config.login_attempted:
                form.password.errors = ["Too much login attemptes , you are blocked , contact the admin"]
                return render_template('login.html', form=form)
            curl = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            curl.execute("SELECT * FROM users WHERE username=%s", (username,))
            user = curl.fetchone()
            curl.close()

            if len(user) > 0:
                if bcrypt.checkpw(password, user["password"].encode('utf-8')):
                    session['username'] = user['username']
                    return redirect(url_for('home'))
                else:
                    counter += 1
                    form.password.errors = ["Error password and username not match"]
                    return render_template('login.html', form=form)
            else:
                form.username.errors = ["Username not found"]
                return render_template('login.html', form=form)
    return render_template('login.html', form=form)


@app.route('/logout', methods=["GET", "POST"])
def logout():
    session.clear()
    return render_template("home.html")


@app.route('/change_password', methods=["GET", "POST"])
def change_password():
    form = ChangePasswordForm()
    curl = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur = mysql.connection.cursor()
    curl.execute("SELECT password FROM users WHERE username = %s;", (session['username'],))
    exist_password = curl.fetchone()
    if form.validate_on_submit():
        if bcrypt.checkpw(form.currPassword.data.encode('utf-8'), exist_password["password"].encode('utf-8')):
            newPass_hash_password = bcrypt.hashpw(form.newPassword.data.encode('utf-8'), bcrypt.gensalt())
            wasUsed = check_if_password_used_before(session['username'], form.newPassword.data.encode('utf-8'))
            if wasUsed is False:
                cur.execute("UPDATE users SET password = %s WHERE username = %s",
                            (newPass_hash_password, session['username'],))
                mysql.connection.commit()
                update_new_password_in_json(session['username'], newPass_hash_password)
                return redirect(url_for('home'))
            else:
                form.newPassword.errors = ["This new password is already used before"]
                return render_template('change_password.html', form=form)
        else:
            form.currPassword.errors = ["Correct password incorrect"]
            return render_template("change_password.html", form=form)
    return render_template("change_password.html", form=form)


def read_users_from_json():
    with open('users.json') as f:
        data = json.load(f)
    return data


def check_if_password_used_before(username, new_password):
    with open('users.json') as f:
        data = json.load(f)
    passwords = data[username][-config.password_num_of_history:]
    for password in passwords:
        if bcrypt.checkpw(new_password, password.encode('utf-8')):
            return True
    return False


def update_new_password_in_json(username, password):
    data = read_users_from_json()
    data[username].append(password.decode('utf-8'))
    with open('users.json', 'w') as outfile:
        json.dump(data, outfile)


def save_password_in_json(username, password):
    data = read_users_from_json()
    data[str(username)] = []
    data[str(username)].append(password.decode('utf-8'))
    with open('users.json', 'w') as outfile:
        json.dump(data, outfile)


@app.route('/register', methods=["GET", "POST"])
def signup():
    form = SignUpForm()
    curl = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    exist_email = curl.execute("SELECT * FROM users WHERE email=%s", (form.email.data,))
    exist_username = curl.execute("SELECT * FROM users WHERE username=%s", (form.username.data,))
    if form.validate_on_submit():
        if prevent is False:
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO users (username,email,password) VALUES (%s,%s,%s)" , (form.username.data, form.email.data, form.password.data))
            mysql.connection.commit()
            session['username'] = request.form['username']
            return redirect(url_for('home'))
        else:
            if form.password.data in config.password_dictionary:
                form.password.errors = ["This is a common password , please use a new one"]
                return render_template('register.html', form=form)
            if exist_email:
                form.password.errors = ["This Email is already exist!"]
                return render_template('register.html', form=form)
            if exist_username:
                form.username.errors = ["This Username is already exist!"]
                return render_template('register.html', form=form)
            hash_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt())
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO users (username, email, password) VALUES (%s,%s,%s)",
                        (form.username.data, form.email.data, hash_password,))
            mysql.connection.commit()
            session['username'] = request.form['username']
            save_password_in_json(form.username.data, hash_password)
            return redirect(url_for('home'))
    return render_template('register.html', form=form)


def randomString(stringLength=8):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))


@app.route('/client', methods=["GET", "POST"])
def client():
    if request.method == 'POST':

        name = request.form['name']
        phone = request.form['phone']
        cur = mysql.connection.cursor()
        if prevent is False:
            cur.execute("INSERT INTO client (FirstName,phone) VALUES (%s,%s)" % (name, phone))
        else:
            cur.execute("INSERT INTO client (FirstName,phone) VALUES (%s,%s)", (name, phone,))
        mysql.connection.commit()
        session['name'] = name
        session['phone'] = phone
        session['client'] = 'yes'
        return render_template("home.html")
    else:
        return render_template("home.html")


@app.route('/forgot', methods=["GET", "POST"])
def forgot():
    if request.method == 'POST':
        email = request.form['email']
        session['email'] = email
        h = hashlib.sha1(randomString().encode('utf-8'))
        session['code'] = str(h.hexdigest())
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.ehlo()
        server.starttls()
        server.login("cybercourse1234", "Cyber!@#")
        server.sendmail(
            "cybercourse1234@gmail.com",
            email,
            str(h.hexdigest()))
        server.quit()
        return render_template("chackCode.html")
    else:
        return render_template("forgotPwd.html")


@app.route('/confirm', methods=["GET", "POST"])
def confirm():
    if request.method == 'POST':
        code = request.form['code']
        if session.get("code") == code:
            form = ChangePasswordForm()
            curl = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            curl.execute("SELECT * FROM users WHERE email=%s", (session['email'],))
            user = curl.fetchone()
            session['username'] = user['username']
            return render_template("change_password.html", form=form)
    else:
        return render_template("forgotPwd.html")


if __name__ == '__main__':
    counter = 0
    app.secret_key = "^A%DJAJU^JJ123"
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_cert_chain('server.crt', 'server.key')
    app.run(host='localhost', port=8080, ssl_context=context, threaded=True, debug=True)
