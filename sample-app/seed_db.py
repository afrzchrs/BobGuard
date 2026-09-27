from db import get_connection, init_db

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
print("Database initialized.")
