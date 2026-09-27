import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).with_name("sentryheal.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            secret_note TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
