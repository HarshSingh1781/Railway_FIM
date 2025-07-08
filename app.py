from flask import Flask, render_template, request, redirect, jsonify, send_file, session, url_for, flash
import sqlite3, os
import pandas as pd
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
app.secret_key = 'your_super_secret_key_here'  # ✅ REQUIRED for sessions and serializer
app.config['UPLOAD_FOLDER'] = 'uploads'
DB = 'database.db'
serializer = URLSafeTimedSerializer(app.secret_key)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ------------------ Database Setup ------------------
def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL,
                file_code TEXT UNIQUE NOT NULL,
                tags TEXT,
                cabinet TEXT,
                shelf TEXT,
                box TEXT,
                is_deleted INTEGER DEFAULT 0
            )
        ''')
        conn.commit()

# ------------------- Login Required Decorator -------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash("Please login first.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ------------------- Routes -------------------
@app.route('/')
@login_required
def home():
    return render_template('file_form.html', mode='add', form_action='/add', file=None)

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
            flash("Error: Duplicate file code.", "danger")
    return redirect('/')

@app.route('/api/search')
@login_required
def search():
    query = request.args.get('q', '').lower()
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM files WHERE is_deleted = 0 AND (LOWER(file_name) LIKE ? OR LOWER(file_code) LIKE ?)",
                  (f'%{query}%', f'%{query}%'))
        rows = c.fetchall()
        return jsonify([{
            'file_name': r[1],
            'file_code': r[2],
            'tags': r[3],
            'location': f"{r[4]} > {r[5]} > {r[6]}"
        } for r in rows])

@app.route('/edit/<file_code>', methods=['GET', 'POST'])
@login_required
def edit_file(file_code):
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        if request.method == 'POST':
            data = request.form
            c.execute('''UPDATE files SET file_name=?, tags=?, cabinet=?, shelf=?, box=?
                         WHERE file_code=?''',
                      (data['file_name'], data['tags'], data['cabinet'], data['shelf'], data['box'], file_code))
            conn.commit()
            flash("File updated successfully!", "info")
            return redirect('/search')
        else:
            c.execute("SELECT * FROM files WHERE file_code=?", (file_code,))
            file_row = c.fetchone()
            if not file_row:
                flash("File not found.", "danger")
                return redirect('/search')
            # Map DB row to dict for template
            file = {
                'file_name': file_row[1],
                'file_code': file_row[2],
                'tags': file_row[3],
                'cabinet': file_row[4],
                'shelf': file_row[5],
                'box': file_row[6]
            }
            return render_template('file_form.html', mode='edit', form_action=url_for('edit_file', file_code=file_code), file=file)

@app.route('/export')
@login_required
def export_excel():
    with sqlite3.connect(DB) as conn:
        df = pd.read_sql_query("SELECT * FROM files WHERE is_deleted = 0", conn)
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
            for _, row in df.iterrows():
                try:
                    conn.execute('''INSERT INTO files (file_name, file_code, tags, cabinet, shelf, box)
                                    VALUES (?, ?, ?, ?, ?, ?)''',
                                 (row['file_name'], row['file_code'], row['tags'],
                                  row['cabinet'], row['shelf'], row['box']))
                    conn.commit()
                except sqlite3.IntegrityError:
                    continue
        flash("Excel file imported successfully!", "success")
        return redirect('/')
    flash("Invalid file format. Please upload a .xlsx file.", "danger")
    return redirect('/')

# ------------------- Recycle Bin -------------------
@app.route('/delete/<file_code>')
@login_required
def delete_file(file_code):
    with sqlite3.connect(DB) as conn:
        conn.execute("UPDATE files SET is_deleted = 1 WHERE file_code = ?", (file_code,))
        conn.commit()
    flash("File moved to recycle bin.", "warning")
    return redirect('/search')

@app.route('/recycle-bin')
@login_required
def recycle_bin():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM files WHERE is_deleted = 1")
        files = c.fetchall()
    return render_template('recycle_bin.html', files=files)

@app.route('/restore/<file_code>')
@login_required
def restore_file(file_code):
    with sqlite3.connect(DB) as conn:
        conn.execute("UPDATE files SET is_deleted = 0 WHERE file_code = ?", (file_code,))
        conn.commit()
    flash("File restored successfully.", "success")
    return redirect('/recycle-bin')

@app.route('/permanent-delete/<file_code>')
@login_required
def permanent_delete(file_code):
    with sqlite3.connect(DB) as conn:
        conn.execute("DELETE FROM files WHERE file_code = ?", (file_code,))
        conn.commit()
    flash("File permanently deleted.", "danger")
    return redirect('/recycle-bin')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = request.form['password']
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            c.execute("SELECT password FROM users WHERE username=?", (uname,))
            user = c.fetchone()
            if user and check_password_hash(user[0], pwd):
                session['user'] = uname
                flash("Login successful!", "success")
                return redirect('/')
            flash("Invalid credentials.", "danger")
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    import re
    if request.method == 'POST':
        uname = request.form['username']
        pwd = request.form['password']
        confirm_pwd = request.form['confirm_password']
        email_pattern = r"^[\w\.-]+@[\w\.-]+\.\w{2,}$"
        phone_pattern = r"^\d{10}$"
        if not (re.match(email_pattern, uname) or re.match(phone_pattern, uname)):
            flash("Username must be a valid Email ID or 10-digit Phone Number.", "danger")
            return render_template('signup.html')
        if pwd != confirm_pwd:
            flash("Passwords do not match.", "danger")
            return render_template('signup.html')
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            # Case-insensitive check for email usernames
            if re.match(email_pattern, uname):
                c.execute("SELECT * FROM users WHERE LOWER(username)=LOWER(?)", (uname,))
            else:
                c.execute("SELECT * FROM users WHERE username=?", (uname,))
            if c.fetchone():
                flash("An account with this Email ID or Phone Number already exists.", "danger")
                return render_template('signup.html')
            hashed_pwd = generate_password_hash(pwd)
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (uname, hashed_pwd))
            conn.commit()
            flash("Signup successful! Please login.", "success")
            return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        uname = request.form['username']
        new_pwd = request.form['new_password']
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username=?", (uname,))
            if not c.fetchone():
                flash("Username not found.", "danger")
                return render_template('forgot.html')
            hashed_pwd = generate_password_hash(new_pwd)
            c.execute("UPDATE users SET password=? WHERE username=?", (hashed_pwd, uname))
            conn.commit()
            # Set a special category for password reset so it can be filtered out in the template
            flash("Password reset successful! Please login.", "password_reset")
            return redirect(url_for('login'))
    return render_template('forgot.html')

@app.route('/reset_password', methods=['GET'])
def reset_password():
    return render_template('reset_password.html')

@app.route('/file_details/<file_code>')
@login_required
def file_details(file_code):
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM files WHERE file_code=?", (file_code,))
        file = c.fetchone()
    if not file:
        flash("File not found.", "danger")
        return redirect('/search')
    return render_template('file_details.html', file=file)

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
