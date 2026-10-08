import sqlite3
from typing import Optional, Tuple

def init_db(db_path: str = ":memory:") -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT)")
    cursor.execute("INSERT INTO users (username, role) VALUES ('admin', 'superuser'), ('alice', 'user')")
    conn.commit()
    return conn

def get_user_vulnerable(conn: sqlite3.Connection, username: str) -> Optional[Tuple]:
    """VULNERABLE: Direct SQL string concatenation (CWE-89 / SQL Injection)."""
    cursor = conn.cursor()
    query = f"SELECT id, username, role FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()

def get_user_secure(conn: sqlite3.Connection, username: str) -> Optional[Tuple]:
    """SECURE: Parameterized Query."""
    cursor = conn.cursor()
    query = "SELECT id, username, role FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchone()
