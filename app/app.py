"""
Учебное УЯЗВИМОЕ приложение для пет-проекта AppSec.
Уязвимости заложены специально. Никогда не запускай его в открытой сети.
"""
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)

# Уязвимость: захардкоженный секрет (должен ловить Semgrep)
app.config["SECRET_KEY"] = "super-secret-key-12345"
ADMIN_PASSWORD = "admin123"


def get_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER, name TEXT, email TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'alice', 'alice@example.com')")
    conn.execute("INSERT INTO users VALUES (2, 'bob', 'bob@example.com')")
    return conn


@app.route("/")
def index():
    return """
    <h1>Vuln Shop</h1>
    <ul>
      <li><a href="/search?q=test">Поиск</a></li>
      <li><a href="/user?id=1">Пользователь</a></li>
      <li><a href="/ping?host=127.0.0.1">Ping</a></li>
    </ul>
    <form action="/search"><input name="q"><button>Найти</button></form>
    """


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # Уязвимость: отражённый XSS — ввод вставляется в HTML без экранирования
    return f"<h2>Результаты поиска: {q}</h2>"


@app.route("/user")
def user():
    user_id = request.args.get("id", "1")
    conn = get_db()
    # Уязвимость: SQL-инъекция — ввод склеивается в запрос
    rows = conn.execute("SELECT name, email FROM users WHERE id = " + user_id).fetchall()
    return {"users": rows}


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # Уязвимость: командная инъекция — shell=True и ввод пользователя
    out = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True, text=True)
    return f"<pre>{out.stdout}</pre>"


@app.route("/debug")
def debug():
    # Уязвимость: открытая отладочная страница с секретами (цель для Nuclei)
    return {"debug": True, "secret_key": app.config["SECRET_KEY"], "admin_password": ADMIN_PASSWORD}


if __name__ == "__main__":
    # Уязвимость: debug-режим Flask
    app.run(host="0.0.0.0", port=5000, debug=True)
