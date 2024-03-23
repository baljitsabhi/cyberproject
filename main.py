from flask import Flask, render_template, request, redirect, url_for, session,flash
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import uuid
import bcrypt 
from flask_mail import Mail, Message
import random

app = Flask(__name__)
mail = Mail(app)


# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = '1a2b3c4d5e6d7g8h9i10'

# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'abc123' #Replace ******* with  your database password.
app.config['MYSQL_DB'] = 'loginapp'

# Mail configuration - Updated with your details
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Gmail's SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'group6vu@gmail.com'
app.config['MAIL_PASSWORD'] = 'pnjj rljx lpic igjr'  # Consider using app-specific passwords for better security
app.config['MAIL_DEFAULT_SENDER'] = 'group6vu@gmail.com'

# Initialize Flask extensions
mail.init_app(app)


# Intialize MySQL
mysql = MySQL(app)

@app.route('/')
def index():
    return render_template('home/index.html') 

# http://localhost:5000/pythonlogin/ - this will be the login page, we need to use both GET and POST requests
@app.route('/pythonlogin/', methods=['GET', 'POST'])
def login():
    # Existing login logic
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        # Initialize account variable
        account = None
        
        # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', [username])
        account = cursor.fetchone()

        # Your existing account verification logic
        
        if account and bcrypt.checkpw(password.encode('utf-8'), account['password'].encode('utf-8')):
            # Instead of logging the user in immediately, send a verification code
            verification_code = str(random.randint(1000, 9999))  # Generate a 4-digit code
            session['verification_code'] = verification_code  # Store the code in the session
            session['temp_user'] = account['id']  # Temporarily store the user ID
            
            # Use your send_verification_email function to send the code
            send_verification_email(account['email'], verification_code)
            
            # Redirect to a new route for code verification
            return redirect(url_for('verify_login'))
        else:
            # Account doesn't exist or username/password incorrect
            flash("Incorrect username/password!", "danger")
    
    return render_template('auth/login.html', title="Login")

@app.route('/verify_login', methods=['GET', 'POST'])
def verify_login():
    if request.method == 'POST':
        # Retrieve the user-provided code from the form
        user_code = request.form.get('code')
        
        # Check if the provided code matches the code stored in the session
        if 'verification_code' in session and user_code == session['verification_code']:
            # Retrieve the temporarily stored user ID
            user_id = session.pop('temp_user', None)
            # Remove the verification code from the session
            session.pop('verification_code', None)
            
            if user_id:
                # Fetch the user's details from the database using the user_id
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('SELECT * FROM accounts WHERE id = %s', [user_id])
                account = cursor.fetchone()
                
                # Assuming the account is found, set the necessary session variables
                if account:
                    session['loggedin'] = True
                    session['id'] = account['id']
                    session['username'] = account['username']
                    
                    # Redirect to the home page or another appropriate page
                    return redirect(url_for('home'))
                else:
                    flash("Account not found. Please try again.", "error")
                    return redirect(url_for('login'))
            else:
                flash("Session expired. Please log in again.", "error")
                return redirect(url_for('login'))
        else:
            # The verification code does not match
            flash("Invalid verification code. Please try again.", "error")
            
    # For GET requests or if verification fails, render the verification code entry page again
    return render_template('verify_login.html')


# Define the send_verification_email function
def send_verification_email(email, code):
    msg = Message(subject="Verify Your Email Address",
                  sender=app.config['MAIL_DEFAULT_SENDER'],
                  recipients=[email],
                  body=f"Your verification code is: {code}")
    mail.send(msg)

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
        
        # After all validations pass:
        verification_code = str(random.randint(100000, 999999))  # Generate a 6-digit verification code
        session['verification_code'] = verification_code  # Store the code in the session
        session['temp_user'] = {'username': username, 'password': password, 'email': email, 'phone': phone}  # Temporarily store user details
        
        send_verification_email(email, verification_code)  # Send the verification code via email
        
        flash("Verification code sent to your email. Please enter the code to complete registration.", "info")
        return redirect(url_for('verify'))  # Redirect to verification page (you need to create this route and template)

    return render_template('auth/register.html', title="Register", validation_errors=validation_errors)

# Add a new route for the verification page where users input the verification code
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        user_code = request.form['verification_code']
        if 'verification_code' in session and user_code == session['verification_code']:
            # Verification code matches, proceed with registration
            user_details = session.pop('temp_user', None)
            if user_details:
                # Insert user into the database here using user_details
                # Make sure to hash the password before storing it
                hashed_password = bcrypt.hashpw(user_details['password'].encode('utf-8'), bcrypt.gensalt())
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('INSERT INTO accounts (username, email, password, phone) VALUES (%s, %s, %s, %s)',
                               (user_details['username'], user_details['email'], hashed_password.decode('utf-8'), user_details['phone']))
                mysql.connection.commit()
                flash("You have successfully registered!", "success")
                return redirect(url_for('login'))
            else:
                flash("Session expired. Please register again.", "error")
                return redirect(url_for('register'))
        else:
            flash("Invalid verification code. Please try again.", "danger")
            return render_template('verify.html')  # Show the verification form again

    return render_template('verify.html')  # The initial GET request to show the form



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
        if username == 'User' and password == 'Password123':
            session['logged_in'] = True
            # Redirect to admin dashboard if successful
            # This assumes the redirection itself doesn't cause issues with Hydra's detection mechanism
            return redirect(url_for('admin_dashboard'))
        else:
            # Return a 200 OK status code with a specific message indicating login failure
            # This replaces the previous 401 Unauthorized status code
            return 'Invalid credentials, please try again.', 200  # Note the 200 status code here

    # For GET requests, show the login form
    return render_template('admin_login.html')


@app.route('/admin_dashboard')
def admin_dashboard():
    # Check if the user is logged in
    if not session.get('logged_in'):
        # If not, redirect to the login page
        return redirect(url_for('admin_login'))
    # If logged in, show the dashboard
    return render_template('admin_dashboard.html')

# Add this route for the logout functionality
@app.route('/admin_dashboard/logout')
def admin_logout():
    # Remove user info from the session
    session.pop('logged_in', None)
    # Redirect to login page
    return redirect(url_for('admin_login'))

# ... (existing code)

# Add this route to display all users in the user management section
@app.route('/admin_dashboard/users')
def display_users():
    # Check if the user is logged in
    if not session.get('logged_in'):
        # If not, redirect to the login page
        return redirect(url_for('admin_login'))

    # Fetch all users from the database (replace this with your actual data fetching logic)
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM accounts')
    users = cursor.fetchall()

    # Render the template with user data
    return render_template('users.html', users=users, title="User Management")

@app.route('/models/')
def models():
    return render_template('models.html')



if __name__ =='__main__':
	app.run(debug=True)
