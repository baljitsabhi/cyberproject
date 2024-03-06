from flask import Flask, render_template, request, redirect, url_for, session,flash
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import uuid
import bcrypt 

app = Flask(__name__)

# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = '1a2b3c4d5e6d7g8h9i10'

# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'abc123' #Replace ******* with  your database password.
app.config['MYSQL_DB'] = 'loginapp'


# Intialize MySQL
mysql = MySQL(app)

@app.route('/')
def index():
    return render_template('home/index.html') 

# http://localhost:5000/pythonlogin/ - this will be the login page, we need to use both GET and POST requests
@app.route('/pythonlogin/', methods=['GET', 'POST'])
def login():
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        
        # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', [username])
        # Fetch one record and return result
        account = cursor.fetchone()
        
        # If account exists in accounts table in our database
        if account and bcrypt.checkpw(password.encode('utf-8'), account['password'].encode('utf-8')):
            # Create session data, we can access this data in other routes
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            session['user_id'] = str(uuid.uuid4())  # Generate a unique session ID
            
            # Redirect to home page
            return redirect(url_for('home'))
        else:
            # Account doesn't exist or username/password incorrect
            flash("Incorrect username/password!", "danger")
    
    return render_template('auth/login.html', title="Login")


# http://localhost:5000/pythonlogin/register 
# This will be the registration page, we need to use both GET and POST requests
@app.route('/pythonlogin/register', methods=['GET', 'POST'])
def register():
    validation_errors = {'username': '', 'password': '', 'confirm_password': '', 'email': '', 'phone': ''}
    
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form and 'confirm_password' in request.form and 'phone' in request.form:
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']
        phone = request.form['phone']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
         # Username validation: only allows letters and underscores
        if not re.match(r'^[A-Za-z_]+$', username):
            validation_errors['username'] = "Username must contain only letters and underscores."
        
        # Simple check for minimum length of 8 characters
        if len(password) < 8:
            validation_errors['password'] = "Password must be at least 8 characters long."
        
        if password != confirm_password:
            validation_errors['confirm_password'] = "Passwords do not match."

        
        # Check for existing username
        cursor.execute("SELECT * FROM accounts WHERE username = %s", [username])
        if cursor.fetchone():
            validation_errors['username'] = "Username already exists!"
            
        
        # Check for existing email
        cursor.execute("SELECT * FROM accounts WHERE email = %s", [email])
        if cursor.fetchone():
            validation_errors['email'] = " Email already in use! "
           

        # Check for existing phone number
        cursor.execute("SELECT * FROM accounts WHERE phone = %s", [phone])
        if cursor.fetchone():
            validation_errors['phone'] = "Phone number already in use!"
            
        
        # Phone number validation: only allows numbers and must be exactly 10 digits
        if not re.match(r'^\d{10}$', phone):
            validation_errors['phone'] ="Phone number must contain exactly 10 digits!"
            
        # If there are any errors, render the template with validation_errors
        if any(value for value in validation_errors.values()):
            return render_template('auth/register.html', title="Register", validation_errors=validation_errors)

        

        # Hash the password before storing it
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Validation passed, insert new account with hashed password
        cursor.execute('INSERT INTO accounts (username, email, password, phone) VALUES (%s, %s, %s, %s)', (username, email, hashed_password.decode('utf-8'), phone))
        mysql.connection.commit()
        flash("You have successfully registered!", "success")
        return redirect(url_for('login'))
    else:
        # Handle GET requests or incomplete POST requests
        flash("Please fill out the form!", "danger")
    return render_template('auth/register.html', title="Register",validation_errors=validation_errors)

# http://localhost:5000/pythinlogin/home 
# This will be the home page, only accessible for loggedin users

@app.route('/home')
def home():
    # Check if user is loggedin
    if 'loggedin' in session:
        # User is loggedin show them the home page
        return render_template('home/home.html', username=session['username'],title="Home")
    # User is not loggedin redirect to login page
    return redirect(url_for('index'))    


@app.route('/profile')
def profile():
    # Check if user is loggedin
    if 'loggedin' in session:
        # Assuming you also store email and phone in the session when the user logs in
        # If not, you'll need to fetch these from your database
        email = session.get('email', 'Not provided')
        phone = session.get('phone', 'Not provided')
        session_id = session.get('user_id', 'No session ID')
        
        # User is loggedin show them the profile page with all details
        return render_template('auth/profile.html', username=session['username'], email=email, phone=phone,session_id=session_id, title="Profile")
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

@app.route('/update_password', methods=['POST'])
def update_password():
    if 'loggedin' in session:
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT password FROM accounts WHERE id = %s', [session['id']])
        account = cursor.fetchone()

        if account and bcrypt.checkpw(old_password.encode('utf-8'), account['password'].encode('utf-8')):
            # Hash the new password before storing it
            hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            
            # Update the password in the database
            cursor.execute('UPDATE accounts SET password = %s WHERE id = %s', (hashed_new_password, session['id']))
            mysql.connection.commit()
            flash('Password updated successfully!', 'success')
        else:
            flash('Old password is incorrect.', 'error')
        
        return redirect(url_for('profile'))
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    # Debug: Print session before clearing
    print("Session before clearing:", session)
    
    # Remove user info from the session
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    
    # Debug: Print session after clearing
    print("Session after clearing:", session)
    
    # Redirect to login page
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

if __name__ =='__main__':
	app.run(debug=True)
