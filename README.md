# Flask File Indexing System

A modern, user-friendly file indexing and management system built with Flask, Bootstrap, and SQLite. Features include user authentication, file add/search/edit/delete, recycle bin, Excel import/export, and detailed file views.

## Features

- User authentication (Sign Up, Login, Forgot Password)
- Add, edit, and search files with tags and location (cabinet, shelf, box)
- Soft delete (Recycle Bin) with restore and permanent delete
- Import/export files via Excel
- View file details on a dedicated page
- Responsive, modern UI with Bootstrap

## Project Structure

```
your_project/
│
├── app.py
├── database.db
├── file_index.db
├── requirements.txt
├── templates/
│   ├── add_file.html
│   ├── edit_file.html
│   ├── file_details.html
│   ├── forgot.html
│   ├── login.html
│   ├── recycle_bin.html
│   ├── search_file.html
│   └── signup.html
├── uploads/
│   └── exported_files.xlsx
```

## Setup & Usage

1. **Clone or Download** the project folder.
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
3. **Run the app:**
   ```bash
   python app.py
   ```
4. **Open your browser:**
   Go to [http://127.0.0.1:5000](http://127.0.0.1:5000)

## Requirements

- Python 3.8+
- Flask
- pandas
- werkzeug
- openpyxl

## Notes

- The database (`database.db`) is created automatically on first run.
- Uploaded Excel files and exports are stored in the `uploads/` folder.
- For production, set a strong `app.secret_key` in `app.py`.

## Screenshots

- Login/Signup: Modern, tabbed, purple-themed UI
- Add/Search/Edit: Clean Bootstrap forms
- Recycle Bin: Restore or permanently delete files
- File Details: View all file info on a dedicated page

## License

MIT

---

**Made with Flask & Bootstrap.**
