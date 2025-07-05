from flask import Flask, render_template, request, redirect, jsonify, send_file, session, flash, url_for, get_flashed_messages
import sqlite3, os, json
import pandas as pd
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps


app = Flask(__name__)
app.secret_key = 'yK@p1A$9vTz3!mB2#qW8^LrXeCfHsJ0u'
app.config['UPLOAD_FOLDER'] = 'uploads'
DB = 'database.db'


os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# ------------------- DB Setup -------------------
def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT NOT NULL,
            file_code TEXT UNIQUE NOT NULL,
            tags TEXT,
            cabinet TEXT,
            shelf TEXT,
            box TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )''')
        conn.commit()


# ------------------- Auth Middleware -------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            flash('Login required.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# ------------------- Auth Routes -------------------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed = generate_password_hash(password)
        try:
            with sqlite3.connect(DB) as conn:
                conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
                conn.commit()
                flash('Signup successful! You can now login.', 'signup')
        except sqlite3.IntegrityError:
            flash('Username already exists. Try a different one.', 'signup')
    categories = [cat for cat, msg in get_flashed_messages(with_categories=True)]
    return render_template('login.html', flash_categories=json.dumps(categories))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect(DB) as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user[2], password):
            session['user'] = username
            flash('Login successful!', 'login')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials. Try again.', 'login')
    categories = [cat for cat, msg in get_flashed_messages(with_categories=True)]
    return render_template('login.html', flash_categories=json.dumps(categories))


@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))


# ------------------- Core Routes -------------------
@app.route('/')
@login_required
def home():
    return render_template('add_file.html', username=session.get('user'))


@app.route('/search')
@login_required
def search_page():
    return render_template('search_file.html')


@app.route('/add', methods=['POST'])
@login_required
def add_file():
    data = request.form
    with sqlite3.connect(DB) as conn:
        try:
            conn.execute('''INSERT INTO files (file_name, file_code, tags, cabinet, shelf, box)
                            VALUES (?, ?, ?, ?, ?, ?)''',
                         (data['file_name'], data['file_code'], data['tags'],
                          data['cabinet'], data['shelf'], data['box']))
            conn.commit()
            flash("File added successfully!", "success")
        except sqlite3.IntegrityError:
            flash("Duplicate file code.", "danger")
    return redirect(url_for('home'))


@app.route('/api/search')
@login_required
def search():
    query = request.args.get('q', '').lower()
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM files WHERE LOWER(file_name) LIKE ? OR LOWER(file_code) LIKE ?",
                  (f'%{query}%', f'%{query}%'))
        rows = c.fetchall()
        return jsonify([
            {
                'file_name': r[1],
                'file_code': r[2],
                'tags': r[3],
                'location': f"{r[4]} > {r[5]} > {r[6]}"
            } for r in rows
        ])


@app.route('/export')
@login_required
def export_excel():
    with sqlite3.connect(DB) as conn:
        df = pd.read_sql_query("SELECT * FROM files", conn)
        path = os.path.join(app.config['UPLOAD_FOLDER'], 'exported_files.xlsx')
        df.to_excel(path, index=False)
        return send_file(path, as_attachment=True)


@app.route('/import', methods=['POST'])
@login_required
def import_excel():
    file = request.files['excel_file']
    if file and file.filename.endswith('.xlsx'):
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
        file.save(filepath)
        df = pd.read_excel(filepath)
        with sqlite3.connect(DB) as conn:
            df.to_sql('files', conn, if_exists='append', index=False)
        flash("Excel data imported!", "success")
    else:
        flash("Invalid file type. Please upload .xlsx", "danger")
    return redirect(url_for('home'))


# ------------------- Run App -------------------
if __name__ == '__main__':
    init_db()
    app.run(debug=True)





