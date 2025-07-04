# ✅ FILE: app.py
from flask import Flask, render_template, request, redirect, jsonify, send_file
import sqlite3, os
import pandas as pd
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
DB = 'database.db'

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ------------------- DB Setup -------------------
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
                box TEXT
            )
        ''')
        conn.commit()

# ------------------- Routes -------------------
@app.route('/')
def home():
    return render_template('add_file.html')

@app.route('/search')
def search_page():
    return render_template('search_file.html')

@app.route('/add', methods=['POST'])
def add_file():
    data = request.form
    with sqlite3.connect(DB) as conn:
        try:
            conn.execute('''INSERT INTO files (file_name, file_code, tags, cabinet, shelf, box)
                            VALUES (?, ?, ?, ?, ?, ?)''',
                         (data['file_name'], data['file_code'], data['tags'],
                          data['cabinet'], data['shelf'], data['box']))
            conn.commit()
            return redirect('/')
        except sqlite3.IntegrityError:
            return "Error: Duplicate file code."

@app.route('/api/search')
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
def export_excel():
    with sqlite3.connect(DB) as conn:
        df = pd.read_sql_query("SELECT * FROM files", conn)
        path = os.path.join(app.config['UPLOAD_FOLDER'], 'exported_files.xlsx')
        df.to_excel(path, index=False)
        return send_file(path, as_attachment=True)

@app.route('/import', methods=['POST'])
def import_excel():
    file = request.files['excel_file']
    if file and file.filename.endswith('.xlsx'):
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
        file.save(filepath)
        df = pd.read_excel(filepath)
        with sqlite3.connect(DB) as conn:
            df.to_sql('files', conn, if_exists='append', index=False)
        return redirect('/')
    return "Invalid file. Upload a .xlsx file."

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
