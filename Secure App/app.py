# app.py (Secured Version)
from flask import Flask, request, session, redirect, url_for, render_template_string
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'secretkey')  #Remove for production enviroment
csrf = CSRFProtect(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,  # Track by IP
    default_limits=["200 per day", "50 per hour"]  # Optional global limits
)

# Initialize database (users table)
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            bio TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Route: Register new user
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = request.form['password']
        email = request.form['email']
        bio = request.form['bio']
        
        # Hash password before storage
        pwd_hash = generate_password_hash(pwd)
        
        # Parameterized query to prevent SQLi
    
        # 1. Query with placeholders
        query = "INSERT INTO users (username, password, email, bio) VALUES (?, ?, ?, ?)"

        # 2. Connect to the database
        conn = sqlite3.connect('users.db')
        c = conn.cursor()

        try:
            # 3. Execute with parameters
            c.execute(query, (uname, pwd_hash, email, bio))
            conn.commit()

            # 4. Error handling
        except sqlite3.IntegrityError:
            conn.close()
            return "Username already exists"
        except Exception as e:
            conn.close()
            return f"Error: {str(e)}"
        conn.close()
        return redirect(url_for('login'))
    
    # Registration form with CSRF token
    return render_template_string('''
        <h2>Register</h2>
        <form method="post">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          Username: <input name="username" required><br>
          Password: <input name="password" type="password" required><br>
          Email:    <input name="email" type="email"><br>
          Bio:      <input name="bio"><br>
          <input type="submit" value="Register">
        </form>
    ''')

# Route: Login
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = request.form['password']
        
        # Parameterized query
        query = "SELECT * FROM users WHERE username = ?"
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute(query, (uname,))
        user = c.fetchone()
        conn.close()
        
        # Verify password hash
        if user and check_password_hash(user[2], pwd):
            session['user_id'] = user[0]
            return redirect(url_for('profile'))
        else:
            return 'Login failed'
    
    # Login form with CSRF token
    return render_template_string('''
        <h2>Login</h2>
        <form method="post">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          Username: <input name="username" required><br>
          Password: <input name="password" type="password" required><br>
          <input type="submit" value="Login">
        </form>
    ''')
# Route: Customize the 429 error response
@app.errorhandler(429)
def ratelimit_error(e):
    return "Too many login attempts. Please try again later.", 429
# Route: View/Edit Profile
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Parameterized query
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT username, email, bio FROM users WHERE id = ?", (session['user_id'],))
    user = c.fetchone()
    conn.close()
    
    if not user:
        return "User not found"
    
    username, email, bio = user
    
    if request.method == 'POST':
        new_email = request.form['email']
        new_bio = request.form['bio']
        
        # Parameterized update
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("UPDATE users SET email = ?, bio = ? WHERE id = ?",
                 (new_email, new_bio, session['user_id']))
        conn.commit()
        conn.close()
        return redirect(url_for('profile'))
    
    # Profile template with escaped values
    return render_template_string('''
        <h2>Profile of {{ username }}</h2>
        <p>Email: {{ email }}</p>
        <form method="post">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          New Email: <input name="email" value="{{ email }}"><br>
          New Bio:   <input name="bio" value="{{ bio }}"><br>
          <input type="submit" value="Update">
        </form>
    ''', username=username, email=email, bio=bio)

# Route: Logout
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)  # Debug mode disabled

    