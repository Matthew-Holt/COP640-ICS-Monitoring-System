import random
from datetime import datetime
from flask import Flask, render_template, request, redirect, session, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app and configure database and secret key
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ics.db' # Database file is ics.db
app.config['SECRET_KEY'] = 'abc123' # Secret key for session management
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define user model for database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)

# Define environmental result model for database
class EnvironmentalResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    temperature = db.Column(db.Float, nullable=False)
    humidity = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    submitted_by = db.Column(db.String(80), nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

# Create database tables
with app.app_context():
    db.create_all()

# Function to check if current user is an admin
def is_admin():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        return user.is_admin
    return False

# Route for homepage
@app.route('/')
def index():
    # Show the homepage template
    return render_template('index.html')

# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Process registration form data
        username = request.form['username']
        password = request.form['password']
        is_admin = 'admin' in request.form  # Check if admin checkbox is checked

        # Ensure username does not already exist
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('register'))

        # Hash password and create new user record
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful!')
        return redirect(url_for('login'))
    return render_template('register.html')

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Process login form data
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        # Validate login credentials
        if user and check_password_hash(user.password, password):
            # Update last login time and set session variables
            previous_login_time = user.last_login
            user.last_login = datetime.utcnow()
            db.session.commit()

            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            session['previous_login'] = previous_login_time.strftime('%Y-%m-%d %H:%M:%S') if previous_login_time else "This is your first login."
            return redirect(url_for('home')) # Redirect to the home page after successful login
        else:
            flash('Invalid username or password.')
    return render_template('login.html')

# Route for the home page/dashboard for logged-in users
@app.route('/home')
def home():
    # Checks if a user ID is stored in the session (If user is logged in)
    if 'user_id' not in session:
        # Redirects to the login page if no user is found in session (if user is not logged in)
        return redirect('/login')
    
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    if not user:
        # Clears session and redirects to login if the user ID in session doesn't match any user in the database
        session.clear()
        flash('Username or password are incorrect or not found.')
        return redirect('/login')

    # Retrieves the last login time from the user object and passes it to the home template
    last_login = user.last_login if user.last_login else "This is your first login."
    return render_template('home.html', username=session['username'], last_login=session.get('previous_login'))

@app.route('/logout')
def logout():
    # Clears the session, logging the user out
    session.clear()
    return redirect('/')

@app.route('/cloud')
def cloud():
    # Redirects to login if no user is found in session, ensuring this page is accessible only to logged-in users
    if 'user_id' not in session:
        return redirect('/login')
    
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    return render_template('cloud.html')

@app.route('/ics')
def ics():
    # Ensures access to the ICS environmental variables page is restricted to logged-in users
    if 'user_id' not in session:
        return redirect('/login')
    
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    # Generates random environmental data based on the current hour
    current_hour = datetime.now().hour
    random.seed(current_hour)
    
    temperature = random.randint(20, 30)
    humidity = random.randint(30, 60)
    manual_submissions = EnvironmentalResult.query.order_by(EnvironmentalResult.submitted_at.desc()).limit(4).all()
    # Renders the ICS page with temperature, humidity, and manually submitted environmental results
    return render_template('ics.html', temperature=temperature, humidity=humidity, manual_submissions=manual_submissions)

@app.route('/about')
def about():
    # Simple route that renders an about page with no dynamic content
    return render_template('about.html')

@app.route('/admin_panel', methods=['GET', 'POST'])
def admin_panel():
    # Checks for admin privileges before allowing access to the admin panel
    if not session.get('is_admin', False):
        flash('Access denied')
        return redirect(url_for('index'))
    
    # Handles form submissions for entering environmental data manually
    if request.method == 'POST':
        temperature = request.form.get('temperature')
        humidity = request.form.get('humidity')
        # Retrieves the username from session
        submitted_by = session.get('username', 'admin')

        if not temperature or not humidity:
            flash('Temperature and humidity are required.')
            return redirect(url_for('admin_panel'))

        # Creates a new EnvironmentalResult object with the form data
        new_result = EnvironmentalResult(
            temperature=float(temperature),
            humidity=float(humidity),
            submitted_by=submitted_by,
            submitted_at=datetime.utcnow()
        )
        # Adds the new object to the session and commits it to the database
        db.session.add(new_result)
        db.session.commit()
        flash('New environmental result added successfully.')
        # Redirects to the ICS page to view the new entry
        return redirect(url_for('ics'))

    # Renders the admin panel form for GET requests or for admins who are not posting data
    return render_template('admin_panel.html', is_admin=session.get('is_admin', False))

if __name__ == '__main__':
    app.run()