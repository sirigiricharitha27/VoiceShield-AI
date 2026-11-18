import os, sqlite3
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.getenv('DATABASE_PATH', os.path.join(BASE_DIR, 'voiceshield.db'))

def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

def init_db():
    with connect() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          email TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          preferred_language TEXT DEFAULT 'English',
          created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS incidents (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          title TEXT NOT NULL,
          language TEXT DEFAULT 'English',
          category TEXT DEFAULT 'OTHER',
          status TEXT DEFAULT 'UNCLEAR',
          urgency TEXT DEFAULT 'Review',
          summary TEXT DEFAULT '',
          transcript TEXT DEFAULT '',
          analysis_json TEXT DEFAULT '{}',
          guidance TEXT DEFAULT '',
          report_text TEXT DEFAULT '',
          source_type TEXT DEFAULT 'typed',
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS evidence (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          incident_id INTEGER NOT NULL,
          filename TEXT NOT NULL,
          stored_name TEXT NOT NULL,
          mime_type TEXT,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
        );
        ''')
