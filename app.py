from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import random
import string
from datetime import datetime
import threading

app = Flask(__name__)
app.secret_key = 'secret_santa_key'

# Global variable for reveal date
REVEAL_DATE = datetime(2024, 12, 7)
CHRISTMAS_DATE = datetime(2024, 12, 12)  # Christmas date
SYSTEM_LOCKED = False  # Tracks if the system is locked

# Default admin credentials
ADMIN_LOGIN = "admin"
ADMIN_PASSWORD = "adminpassword"

def check_reveal_date():
    """Check if now is >= REVEAL_DATE, shuffle users, and lock the system."""
    global SYSTEM_LOCKED
    now = datetime.now()
    
    if now >= REVEAL_DATE and not SYSTEM_LOCKED:
        conn = get_db_connection()
        users = conn.execute('SELECT id FROM users WHERE username != ?', (ADMIN_LOGIN,)).fetchall()
        user_ids = [user['id'] for user in users]

        # Shuffle users
        reshuffle = True
        while reshuffle:
            reshuffle = False
            shuffled = random.sample(user_ids, len(user_ids))
            for user_id, receiver_id in zip(user_ids, shuffled):
                if user_id == receiver_id:
                    reshuffle = True
                    break

        # Save the valid shuffle into the database
        for user_id, receiver_id in zip(user_ids, shuffled):
            conn.execute('UPDATE users SET secret_receiver_id = ? WHERE id = ?', (receiver_id, user_id))
        conn.commit()
        conn.close()

        # Lock the system
        SYSTEM_LOCKED = True

def get_db_connection():
    conn = sqlite3.connect('secretsanta.db')
    conn.row_factory = sqlite3.Row
    return conn

def generate_secret_nickname():
    return ''.join(random.choices(string.ascii_letters, k=8))

def setup_database():
    """Initialize the database if it doesn't exist."""
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        username TEXT UNIQUE,
                        password TEXT,
                        gender TEXT,
                        preferences TEXT,
                        secret_nickname TEXT,
                        secret_receiver_id INTEGER
                    )''')
    # Ensure the admin user exists
    admin_user = conn.execute('SELECT * FROM users WHERE username = ?', (ADMIN_LOGIN,)).fetchone()
    if not admin_user:
        conn.execute('INSERT INTO users (username, password, gender, secret_nickname) VALUES (?, ?, ?, ?)',
                     (ADMIN_LOGIN, ADMIN_PASSWORD, 'Admin', generate_secret_nickname()))
    conn.commit()
    conn.close()

def get_user_count():
    conn = get_db_connection()
    count = conn.execute('SELECT COUNT(*) FROM users WHERE username != ?', (ADMIN_LOGIN,)).fetchone()[0]
    conn.close()
    return count

# Call this function before app.run()
setup_database()

@app.before_request
def before_request():
    check_reveal_date()


@app.route('/')
def home():
    conn = get_db_connection()
    user_count = conn.execute('SELECT COUNT(*) FROM users WHERE username != ?', (ADMIN_LOGIN,)).fetchone()[0]
    conn.close()
    return render_template('login.html', user_count=user_count, reveal_date=REVEAL_DATE)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
        conn.close()
        if user:
            session['user_id'] = user['id']
            session['is_admin'] = (username == ADMIN_LOGIN)
            return redirect(url_for('admin' if session['is_admin'] else 'dashboard'))
        else:
            flash("Invalid username or password", "error")
    return render_template('login.html', reveal_date=REVEAL_DATE, user_count=get_user_count())



@app.route('/register', methods=['GET', 'POST'])
def register():
    if SYSTEM_LOCKED:
        flash("Registration is closed!", "error")
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        gender = request.form['gender']
        secret_nickname = generate_secret_nickname()

        conn = get_db_connection()
        existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if existing_user:
            flash("Username already exists!", "error")
        else:
            conn.execute('INSERT INTO users (username, password, gender, secret_nickname) VALUES (?, ?, ?, ?)',
                         (username, password, gender, secret_nickname))
            conn.commit()
            flash("Registration successful! Please log in.", "success")
        conn.close()
    return render_template('register.html')


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session or session.get('is_admin'):
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    # Check if reveal date or Christmas has passed
    now = datetime.now()
    receiver = None
    show_own_secret_name = False
    
    if now > REVEAL_DATE:
        # Fetch receiver details
        receiver = conn.execute('SELECT secret_nickname, preferences FROM users WHERE id = ?', 
                                (user['secret_receiver_id'],)).fetchone()
        
        # If it's Christmas or later, show user's own secret name
        if now >= CHRISTMAS_DATE:
            show_own_secret_name = True

    conn.close()
    return render_template('user_dashboard.html', user=user, receiver=receiver, show_own_secret_name=show_own_secret_name)


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'is_admin' not in session or not session['is_admin']:
        return redirect(url_for('login'))

    conn = get_db_connection()
    users = conn.execute('''
        SELECT u.id, u.username, u.gender, u.preferences, u.secret_nickname, 
               r.username AS receiver_username
        FROM users u
        LEFT JOIN users r ON u.secret_receiver_id = r.id
        WHERE u.username != ?
    ''', (ADMIN_LOGIN,)).fetchall()

    if request.method == 'POST' and SYSTEM_LOCKED:
        flash("Edits and deletions are not allowed after the reveal date!", "error")
        return redirect(url_for('admin'))
    
    if request.method == 'POST':
        if 'shuffle' in request.form:
            flash("Shuffling is disabled after the reveal date!", "error")
        elif 'edit_user' in request.form:
            user_id = request.form['user_id']
            preferences = request.form['preferences']
            conn.execute('UPDATE users SET preferences = ? WHERE id = ?', (preferences, user_id))
            conn.commit()
            flash("User updated successfully!", "success")
        elif 'delete_user' in request.form:
            user_id = request.form['user_id']
            conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
            conn.commit()
            flash("User deleted successfully!", "success")
    conn.close()
    return render_template('admin.html', users=users, reveal_date=REVEAL_DATE)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
