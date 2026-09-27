from app import app
from db import get_connection, init_db

def setup_module():
    init_db()
    conn = get_connection()
    conn.execute("DELETE FROM users")
    conn.executemany(
        "INSERT INTO users (id, username, email, secret_note) VALUES (?, ?, ?, ?)",
        [
            (1, "alice", "alice@example.local", "Alice private note"),
            (2, "bob", "bob@example.local", "Bob private note"),
            (3, "charlie", "charlie@example.local", "Charlie private note"),
        ],
    )
    conn.commit()
    conn.close()

def test_home():
    assert app.test_client().get("/").status_code == 200

def test_normal_search():
    r = app.test_client().get("/search?q=alice")
    assert r.status_code == 200
    assert b"alice" in r.data

def test_existing_profile():
    r = app.test_client().get("/profile/1")
    assert r.status_code == 200
    assert b"alice" in r.data

def test_normal_division():
    r = app.test_client().get("/divide?a=10&b=2")
    assert r.status_code == 200
    assert r.get_json()["result"] == 5
