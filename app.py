# app.py (Vulnerable Version)
from flask import Flask, request, session, redirect, url_for, render_template_string
import sqlite3

app = Flask(__name__)
app.secret_key = 'insecure-secret'  # Used for session cookies

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
        pwd   = request.form['password']
        email = request.form['email']
        bio   = request.form['bio']
        # Vulnerable: SQL query built by string concatenation (SQL Injection risk)
        query = f"INSERT INTO users (username,password,email,bio) VALUES ('{uname}','{pwd}','{email}','{bio}')"
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute(query)  # vulnerable execution
            conn.commit()
        except Exception as e:
            conn.close()
            return f"Error: {e}"
        conn.close()
        return redirect(url_for('login'))
    # HTML form for registration (no CSRF protection)
    return '''
        <h2>Register</h2>
        <form method="post">
          Username: <input name="username"><br>
          Password: <input name="password" type="password"><br>
          Email:    <input name="email"><br>
          Bio:      <input name="bio"><br>
          <input type="submit" value="Register">
        </form>
    '''

# Route: Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form['username']
        pwd   = request.form['password']
        # Vulnerable: SQL query with f-string (SQL Injection)
        query = f"SELECT * FROM users WHERE username = '{uname}' AND password = '{pwd}'"
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute(query)   # vulnerable execution
        user = c.fetchone()
        conn.close()
        if user:
            session['user_id'] = user[0]  # store user id in session
            return redirect(url_for('profile'))
        else:
            return 'Login failed'
    return '''
        <h2>Login</h2>
        <form method="post">
          Username: <input name="username"><br>
          Password: <input name="password" type="password"><br>
          <input type="submit" value="Login">
        </form>
    '''

# Route: View/Edit Profile
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute(f"SELECT username, email, bio FROM users WHERE id = {session['user_id']}")  # SQL Injection risk
    user = c.fetchone()
    conn.close()
    if not user:
        return "User not found"
    username, email, bio = user
    if request.method == 'POST':
        new_email = request.form['email']
        new_bio   = request.form['bio']
        # Vulnerable: update with string formatting (SQL Injection)
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute(f"UPDATE users SET email = '{new_email}', bio = '{new_bio}' WHERE id = {session['user_id']}")
        conn.commit()
        conn.close()
        return redirect(url_for('profile'))
    # Vulnerable: using Markup or render_template_string to directly output user input (XSS risk)
    return render_template_string(f"""
        <h2>Profile of {username}</h2>
        <p>Email: {email}</p>
        <form method="post">
          New Email: <input name="email" value="{email}"><br>
          New Bio:   <input name="bio" value="{bio}"><br>
          <input type="submit" value="Update">
        </form>
    """)  # Note: unsanitized {bio} may include <script> and execute

# Route: Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)  # Run in debug mode (insecure for production)
