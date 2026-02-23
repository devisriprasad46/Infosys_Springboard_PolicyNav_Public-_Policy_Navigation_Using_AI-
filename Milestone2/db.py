import sqlite3
import bcrypt
import datetime
import time

DB_NAME = "users.db"
MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_SECONDS = 300

def _ts():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (email TEXT PRIMARY KEY,
                  username TEXT UNIQUE,
                  password BLOB,
                  sec_q TEXT,
                  sec_a TEXT,
                  created_at TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS password_history
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT,
                  password BLOB,
                  set_at TEXT,
                  FOREIGN KEY(email) REFERENCES users(email))''')
    c.execute('''CREATE TABLE IF NOT EXISTS login_attempts
                 (email TEXT PRIMARY KEY,
                  attempts INTEGER,
                  last_attempt REAL)''')
    conn.commit()
    conn.close()
    init_admin()

def init_admin():
    if not check_user_exists("admin@llm.com"):
        register_user("admin@llm.com", "admin", "Admin@123", None, None)

def email_exists(email):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE email = ?", (email,))
    ok = c.fetchone() is not None
    conn.close()
    return ok

def username_exists(username):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    ok = c.fetchone() is not None
    conn.close()
    return ok

def register_user(email, username, password, sec_q, sec_a):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    try:
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        now = _ts()
        c.execute("INSERT INTO users (email, username, password, sec_q, sec_a, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                  (email, username, hashed, sec_q, sec_a, now))
        c.execute("INSERT INTO password_history (email, password, set_at) VALUES (?, ?, ?)", (email, hashed, now))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def get_user_by_email(email):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT email, username, password, sec_q, sec_a FROM users WHERE email = ?", (email,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return {"email": row[0], "username": row[1], "password": row[2], "sec_q": row[3], "sec_a": row[4]}

def update_password(email, new_password):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())
    now = _ts()
    c.execute("UPDATE users SET password = ? WHERE email = ?", (hashed, email))
    c.execute("INSERT INTO password_history (email, password, set_at) VALUES (?, ?, ?)", (email, hashed, now))
    conn.commit()
    conn.close()

def check_password_reused(email, new_password):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT password FROM password_history WHERE email = ?", (email,))
    history = c.fetchall()
    conn.close()
    for (stored_hash,) in history:
        if bcrypt.checkpw(new_password.encode("utf-8"), stored_hash):
            return True
    return False

def check_user_exists(email):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE email = ?", (email,))
    ok = c.fetchone() is not None
    conn.close()
    return ok

def get_login_attempts(email):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT attempts, last_attempt FROM login_attempts WHERE email = ?", (email,))
    data = c.fetchone()
    conn.close()
    return data if data else (0, 0)

def increment_login_attempts(email):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    attempts, _ = get_login_attempts(email)
    new_attempts = attempts + 1
    now = time.time()
    c.execute("INSERT OR REPLACE INTO login_attempts (email, attempts, last_attempt) VALUES (?, ?, ?)", (email, new_attempts, now))
    conn.commit()
    conn.close()

def reset_login_attempts(email):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM login_attempts WHERE email = ?", (email,))
    conn.commit()
    conn.close()

def is_rate_limited(email):
    attempts, last_attempt = get_login_attempts(email)
    if attempts >= MAX_LOGIN_ATTEMPTS:
        if time.time() - last_attempt < LOCKOUT_SECONDS:
            return True, LOCKOUT_SECONDS - (time.time() - last_attempt)
        else:
            reset_login_attempts(email)
    return False, 0

def authenticate_user(email, password):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT password, username FROM users WHERE email = ?", (email,))
    data = c.fetchone()
    conn.close()
    if data:
        stored_hash = data[0]
        if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
            reset_login_attempts(email)
            return True, data[1]
    increment_login_attempts(email)
    return False, None

def get_all_users():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT email, created_at FROM users")
    data = c.fetchall()
    conn.close()
    return data

def delete_user(email):
    if email == "admin@llm.com":
        return False
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE email = ?", (email,))
    c.execute("DELETE FROM password_history WHERE email = ?", (email,))
    c.execute("DELETE FROM login_attempts WHERE email = ?", (email,))
    conn.commit()
    conn.close()
    return True
