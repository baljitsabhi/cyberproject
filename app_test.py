from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re

app = Flask(__name__)

# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = '1a2b3c4d5e6d7g8h9i10'

# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'

# Replace ******* with your database password.
app.config['MYSQL_PASSWORD'] = 'abc123' 
app.config['MYSQL_DB'] = 'loginapp'


# Initialize MySQL
mysql = MySQL(app)

# Define a function to check certain conditions before each request
@app.before_request
def check_request():
    if request.endpoint in ['login', 'register', 'static', 'favicon', 'favicon.ico']:
        return None
    if 'loggedin' not in session:
        return redirect(url_for('login'))

# Login route
@app.route('/pythonlogin/', methods=['GET', 'POST'])
def login():
    # Output message if something goes wrong...
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s AND password = %s', (username, password))
        account = cursor.fetchone()
        if account:
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            return redirect(url_for('home'))
        else:
            flash("Incorrect username/password!", "danger")
    return render_template('auth/login.html', title="Login")

# Registration route
@app.route('/pythonlogin/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM accounts WHERE username LIKE %s", [username])
        account = cursor.fetchone()
        if account:
            flash("Account already exists!", "danger")
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash("Invalid email address!", "danger")
        elif not re.match(r'[A-Za-z0-9]+', username):
            flash("Username must contain only characters and numbers!", "danger")
        elif not username or not password or not email:
            flash("Incorrect username/password!", "danger")
        else:
            cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s)', (username, email, password))
            mysql.connection.commit()
            flash("You have successfully registered!", "success")
            return redirect(url_for('login'))
    elif request.method == 'POST':
        flash("Please fill out the form!", "danger")
    return render_template('auth/register.html', title="Register")

# Home route
@app.route('/')
def index():
    return render_template('home/index')

def home():
    if 'loggedin' in session:
        return render_template('home/home.html', username=session['username'], title="Home")
    return redirect(url_for('login'))

# Profile route
@app.route('/profile')
def profile():
    if 'loggedin' in session:
        return render_template('auth/profile.html', username=session['username'], title="Profile")
    return redirect(url_for('login'))


@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if credentials match the specified admin credentials
        if username == 'Baljit' and password == 'VUsydney':
            session['logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            # Ideally, you would want to give a generic error message here to avoid giving hints to potential attackers
            return 'Invalid credentials', 401

    # For GET requests, show the login form
    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    # Check if the user is logged in
    if not session.get('logged_in'):
        # If not, redirect to the login page
        return redirect(url_for('admin_login'))
    # If logged in, show the dashboard
    return 'Admin Dashboard - Welcome!'


if __name__ == '__main__':
    app.run(debug=True)
