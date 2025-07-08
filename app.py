from flask import Flask, render_template, request, redirect, jsonify, send_file, session, flash
import sqlite3, os
import pandas as pd
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key' 
app.config['UPLOAD_FOLDER'] = 'uploads'
DB = 'database.db'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ------------------ Database Setup ------------------ 
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
                        box TEXT,
                        is_deleted INTEGER DEFAULT 0)''')
        # Ensure is_deleted column exists for old databases
        c.execute("PRAGMA table_info(files)")
        columns = [col[1] for col in c.fetchall()]
        if 'is_deleted' not in columns:
            c.execute("ALTER TABLE files ADD COLUMN is_deleted INTEGER DEFAULT 0")
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL)''')
        conn.commit()

# ------------------ Auth Routes ------------------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = generate_password_hash(request.form['password'])
        with sqlite3.connect(DB) as conn:
            try:
                conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (uname, pwd))
                conn.commit()
                return redirect('/login')
            except:
                return "Username already exists."
    return render_template('signup.html')

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
                return redirect('/')
            return "Invalid credentials"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        uname = request.form['username']
        new_pwd = generate_password_hash(request.form['new_password'])
        with sqlite3.connect(DB) as conn:
            conn.execute("UPDATE users SET password=? WHERE username=?", (new_pwd, uname))
            conn.commit()
        return redirect('/login')
    return render_template('forgot.html')

# ------------------ File Routes ------------------
@app.route('/')
def home():
    if 'user' not in session:
        return redirect('/login')
    return render_template('add_file.html')

@app.route('/add', methods=['POST'])
def add_file():
    if 'user' not in session:
        return redirect('/login')
    data = request.form
    with sqlite3.connect(DB) as conn:
        try:
            conn.execute('''INSERT INTO files (file_name, file_code, tags, cabinet, shelf, box)
                            VALUES (?, ?, ?, ?, ?, ?)''',
                         (data['file_name'], data['file_code'], data['tags'],
                          data['cabinet'], data['shelf'], data['box']))
            conn.commit()
            flash("✅ File added successfully!", "success")
        except sqlite3.IntegrityError:
            flash("❌ Error: Duplicate file code.", "danger")
    return redirect('/')


@app.route('/search')
def search_page():
    if 'user' not in session:
        return redirect('/login')
    return render_template('search_file.html')

@app.route('/api/search')
def search():
    if 'user' not in session:
        return redirect('/login')
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
def edit_file(file_code):
    if 'user' not in session:
        return redirect('/login')
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        if request.method == 'POST':
            data = request.form
            c.execute('''UPDATE files SET file_name=?, tags=?, cabinet=?, shelf=?, box=?
                         WHERE file_code=?''',
                      (data['file_name'], data['tags'], data['cabinet'], data['shelf'], data['box'], file_code))
            conn.commit()
            return redirect('/search')
        else:
            c.execute("SELECT * FROM files WHERE file_code=?", (file_code,))
            file = c.fetchone()
            return render_template('edit_file.html', file=file)

@app.route('/delete/<file_code>')
def delete_file(file_code):
    if 'user' not in session:
        return redirect('/login')
    with sqlite3.connect(DB) as conn:
        conn.execute("UPDATE files SET is_deleted = 1 WHERE file_code = ?", (file_code,))
        conn.commit()
    flash("🗑️ File moved to Recycle Bin!", "warning")
    return redirect('/search')

@app.route('/recycle_bin')
def recycle_bin():
    if 'user' not in session:
        return redirect('/login')
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM files WHERE is_deleted = 1")
        files = c.fetchall()
    return render_template('recycle_bin.html', files=files)

@app.route('/restore/<file_code>')
def restore_file(file_code):
    if 'user' not in session:
        return redirect('/login')
    with sqlite3.connect(DB) as conn:
        conn.execute("UPDATE files SET is_deleted = 0 WHERE file_code = ?", (file_code,))
        conn.commit()
    flash("✅ File restored!", "success")
    return redirect('/recycle_bin')

@app.route('/permanent_delete/<file_code>')
def permanent_delete_file(file_code):
    if 'user' not in session:
        return redirect('/login')
    with sqlite3.connect(DB) as conn:
        conn.execute("DELETE FROM files WHERE file_code = ?", (file_code,))
        conn.commit()
    flash("❌ File permanently deleted!", "danger")
    return redirect('/recycle_bin')

@app.route('/import', methods=['POST'])
def import_excel():
    if 'user' not in session:
        return redirect('/login')
    file = request.files['excel_file']
    if file and file.filename.endswith('.xlsx'):
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
        file.save(filepath)
        df = pd.read_excel(filepath)
        with sqlite3.connect(DB) as conn:
            df.to_sql('files', conn, if_exists='append', index=False)
        return redirect('/')
    return "Invalid file. Upload a .xlsx file."

@app.route('/export')
def export_excel():
    if 'user' not in session:
        return redirect('/login')
    with sqlite3.connect(DB) as conn:
        df = pd.read_sql_query("SELECT * FROM files", conn)
        path = os.path.join(app.config['UPLOAD_FOLDER'], 'exported_files.xlsx')
        df.to_excel(path, index=False)
        return send_file(path, as_attachment=True)

@app.route('/file/<file_code>')
def file_details(file_code):
    if 'user' not in session:
        return redirect('/login')
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT file_name, file_code, tags, cabinet, shelf, box FROM files WHERE file_code = ? AND is_deleted = 0", (file_code,))
        file = c.fetchone()
        if not file:
            flash("File not found or has been deleted.", "danger")
            return redirect('/search')
    return render_template('file_details.html', file=file)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
