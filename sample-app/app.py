from flask import Flask, abort, jsonify, render_template, request
from config import SECRET_KEY
from db import get_connection, init_db

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY

@app.get("/")
def index():
    return render_template("index.html")

@app.get("/search")
def search():
    # A05:2025 Injection - intentionally vulnerable SQL concatenation.
    q = request.args.get("q", "")
    conn = get_connection()
    query = f"SELECT id, username, email FROM users WHERE username LIKE '%{q}%'"
    rows = conn.execute(query).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.get("/profile/<int:user_id>")
def profile(user_id):
    # A01:2025 Broken Access Control - intentionally missing ownership check.
    conn = get_connection()
    row = conn.execute(
        "SELECT id, username, email, secret_note FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    conn.close()
    if row is None:
        abort(404)
    return jsonify(dict(row))

@app.get("/echo")
def echo():
    # A05:2025 Injection / XSS. Unsafe output is in the template.
    message = request.args.get("message", "")
    return render_template("search.html", message=message)

@app.get("/divide")
def divide():
    # A10:2025 Mishandling of Exceptional Conditions.
    a = request.args.get("a", "0")
    b = request.args.get("b", "0")
    try:
        result = float(a) / float(b)
        return jsonify({"result": result})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
