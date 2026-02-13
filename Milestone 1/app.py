
import streamlit as st
import jwt
import datetime
import time
import re
import sqlite3
import sqlite3


# --- Configuration ---
SECRET_KEY = "super_secret_key_for_demo"  # In production, use environment variable
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# --- JWT Utils ---


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# --- Validation Utils ---
def is_valid_email(email):
    # Regex for standard email format
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    try:
        if re.match(pattern, email):
            return True
    except:
        return False
    return False
def is_valid_password(password):
    # Alphanumeric check: must contain letters AND numbers, min length 8
    if len(password) < 8:
        return False
    has_letter = any(ch.isalpha() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    if not (has_letter and has_digit):
        return False
    if not password.isalnum():
        return False
    return True


# --- Session State Management ---


if 'jwt_token' not in st.session_state:
    st.session_state['jwt_token'] = None
if 'page' not in st.session_state:
    st.session_state['page'] = 'login'


# --- Database Utils ---

DB_NAME = 'users.db'
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            sec_q TEXT NOT NULL,
            sec_a TEXT NOT NULL
        )
        '''
    )
    conn.commit()
    conn.close()
def email_exists(email: str) -> bool:
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE email = ?", (email,))
    exists = cur.fetchone() is not None
    conn.close()
    return exists
def username_exists(username: str) -> bool:
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    exists = cur.fetchone() is not None
    conn.close()
    return exists
def create_user(email: str, username: str, password: str, sec_q: str, sec_a: str):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (email, username, password, sec_q, sec_a) VALUES (?, ?, ?, ?, ?)",
        (email, username, password, sec_q, sec_a)
    )
    conn.commit()
    conn.close()
def get_user_by_email(email: str):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT email, username, password, sec_q, sec_a FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return { 'email': row[0], 'username': row[1], 'password': row[2], 'sec_q': row[3], 'sec_a': row[4] }
def update_password(email: str, new_pw: str):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("UPDATE users SET password = ? WHERE email = ?", (new_pw, email))
    conn.commit()
    conn.close()
init_db()


# --- Styling ---

st.set_page_config(page_title="Infosys SpringBoard Intern", page_icon="🤖", layout="wide")

st.markdown('''
    <style>
        .stApp {
            background-color: #0E1117;
        }
        h1 {
            text-align: center;
            color: #4F8BF9;
            font-family: 'Inter', sans-serif;
            margin-bottom: 0.5rem;
        }
        h3 {
            text-align: center;
            color: #FAFAFA;
            font-weight: 300;
            margin-top: 0;
            font-size: 1.2rem;
        }
        .stButton>button {
            width: 100%;
            border-radius: 8px;
            height: 3em;
            background-color: #4F8BF9;
            color: white;
            font-weight: bold;
            border: none;
        }
        .stButton>button:hover {
            background-color: #3b6ccf;
        }
        div[data-testid="stSidebar"] {
            background-color: #262730;
        }
        .error-box {
            background-color: #ffcccc;
            color: #cc0000;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 10px;
        }
        /* Chat message styling */
        .user-msg {
            text-align: right;
            background-color: #262730;
            color: white;
            padding: 10px;
            border-radius: 10px;
            margin: 5px;
            display: inline-block;
            max-width: 80%;
            float: right;
            clear: both;
        }
        .bot-msg {
            text-align: left;
            background-color: #4F8BF9;
            color: white;
            padding: 10px;
            border-radius: 10px;
            margin: 5px;
            display: inline-block;
            max-width: 80%;
            float: left;
            clear: both;
        }
    </style>
''', unsafe_allow_html=True)


# --- Views ---
# --- Login Page ---

def login_page():
    st.markdown("<br>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        st.title("Infosys SpringBoard Intern")
        st.markdown("<h3>Please sign in to continue</h3>", unsafe_allow_html=True)

        with st.form("login_form"):
            email = st.text_input("Email Address")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Sign In")

            if submitted:
                row = get_user_by_email(email)
                if row and row['password'] == password:
                    username = row['username']
                    token = create_access_token({"sub": email, "username": username})
                    st.session_state['jwt_token'] = token
                    st.success("Login successful!")
                    time.sleep(0.5)
                    st.rerun()
                else:
                    st.error("Invalid email or password")

        st.markdown("---")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Forgot Password?"):
                st.session_state['page'] = 'forgot'
                st.rerun()
        with c2:
            if st.button("Create an Account"):
                st.session_state['page'] = 'signup'
                st.rerun()

# --- Signup Page ---

def signup_page():
    st.markdown("<br>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        st.title("Create Account")

        with st.form("signup_form"):
            username = st.text_input("Username (Required)")
            email = st.text_input("Email Address (@domain.com required)")
            password = st.text_input("Password (min 8 chars, alphanumeric)")
            confirm_password = st.text_input("Confirm Password", type="password")
            security_question = st.selectbox("Security Question", [
                "What is your pet name?",
                "What is your mother’s maiden name?",
                "What is your favorite teacher?"
            ])
            security_answer = st.text_input("Security Answer")
            submitted = st.form_submit_button("Sign Up")

            if submitted:
                errors = []

                # Username Validation
                if not username:
                    errors.append("Username is mandatory.")
                elif username_exists(username):
                    errors.append(f"Username '{username}' is already taken.")

                # Email Validation
                if not email:
                    errors.append("Email is mandatory.")
                elif not is_valid_email(email):
                    errors.append("Invalid Email format (e.g. user@domain.com).")
                elif email_exists(email):
                    errors.append(f"Email '{email}' is already registered.")

                # Password Validation
                if not password:
                    errors.append("Password is mandatory.")
                elif not is_valid_password(password):
                    errors.append("Password must be at least 8 characters long and contain only alphanumeric characters.")

                # Confirm Password
                if password != confirm_password:
                    errors.append("Passwords do not match.")

                if not security_answer:
                    errors.append("Security Answer is mandatory.")

                if errors:
                    for error in errors:
                        st.error(error)
                else:
                    # Success
                    create_user(email, username, password, security_question, security_answer)

                    # Auto-login after signup
                    token = create_access_token({"sub": email, "username": username})
                    st.session_state['jwt_token'] = token
                    st.success("Account created successfully!")
                    time.sleep(1)
                    st.rerun()

        st.markdown("---")
        if st.button("Back to Login"):
            st.session_state['page'] = 'login'
            st.rerun()

# --- Forgot Password Page ---

def forgot_password_page():
    st.markdown("<br>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        st.title("Forgot Password")
        if 'reset_stage' not in st.session_state:
            st.session_state['reset_stage'] = 'enter_email'
            st.session_state['reset_email'] = ''
            st.session_state['reset_token'] = None
        stage = st.session_state['reset_stage']
        if stage == 'enter_email':
            with st.form("reset_email_form"):
                email = st.text_input("Email ID")
                submitted = st.form_submit_button("Verify Email")
                if submitted:
                    if not email or not is_valid_email(email):
                        st.error("Enter a valid email.")
                    elif not email_exists(email):
                        st.error("Email not found.")
                    else:
                        st.session_state['reset_email'] = email
                        st.session_state['reset_stage'] = 'verify_answer'
                        st.rerun()
        elif stage == 'verify_answer':
            email = st.session_state['reset_email']
            row = get_user_by_email(email)
            q = row['sec_q'] if row else ''
            with st.form("reset_answer_form"):
                st.text_input("Security Question", value=q, disabled=True)
                ans = st.text_input("Security Answer")
                submitted = st.form_submit_button("Verify Answer")
                if submitted:
                    if not ans:
                        st.error("Security Answer is required.")
                    elif not row or ans != row['sec_a']:
                        st.error("Incorrect answer.")
                    else:
                        st.session_state['reset_token'] = create_access_token({"sub": email, "action": "reset"})
                        st.session_state['reset_stage'] = 'set_new_password'
                        st.rerun()
        elif stage == 'set_new_password':
            email = st.session_state['reset_email']
            token = st.session_state.get('reset_token')
            payload = verify_token(token) if token else None
            if not payload or payload.get('sub') != email:
                st.error("Reset token invalid or expired. Restart process.")
            else:
                with st.form("reset_set_form"):
                    new_pw = st.text_input("New Password")
                    confirm_pw = st.text_input("Confirm New Password", type="password")
                    submitted = st.form_submit_button("Update Password")
                    if submitted:
                        errors = []
                        if not new_pw:
                            errors.append("Password is mandatory.")
                        elif not is_valid_password(new_pw):
                            errors.append("Password must be at least 8 characters long and alphanumeric.")
                        if new_pw != confirm_pw:
                            errors.append("Passwords do not match.")
                        if errors:
                            for e in errors:
                                st.error(e)
                        else:
                            update_password(email, new_pw)
                            st.success("Password updated successfully.")
                            st.session_state['reset_stage'] = 'enter_email'
                            st.session_state['reset_email'] = ''
                            st.session_state['reset_token'] = None
                            time.sleep(1)
                            st.session_state['page'] = 'login'
                            st.rerun()
        st.markdown("---")
        if st.button("Back to Login"):
            st.session_state['page'] = 'login'
            st.rerun()

# --- Dashboard Page ---
def dashboard_page():
    token = st.session_state.get('jwt_token')
    payload = verify_token(token)

    if not payload:
        st.session_state['jwt_token'] = None
        st.warning("Session expired or invalid. Please login again.")
        time.sleep(1)
        st.rerun()
        return
    username = payload.get("username", "User")

    with st.sidebar:
        st.title("🤖 LLM")
        st.markdown("---")
        if st.button("➕ New Chat", use_container_width=True):
             st.info("Started new chat!")

        st.markdown("### History")
        st.markdown("- Project analysis")
        st.markdown("- NLP")
        st.markdown("---")
        st.markdown("### Settings")
        if st.button("Logout", use_container_width=True):
            st.session_state['jwt_token'] = None
            st.rerun()
    # Main Content - Chat Interface
    st.title(f"Welcome, {username}!")
    st.markdown("### How can I help you today?")

    # Chat container (Simple simulation)
    chat_placeholder = st.empty()

    with chat_placeholder.container():
        st.markdown('<div class="bot-msg">Hello! I am LLM. Ask me anything about LLM!</div>', unsafe_allow_html=True)
        # Assuming we might store chat history in session state later

    # User input area at bottom
    with st.form(key='chat_form', clear_on_submit=True):
        col1, col2 = st.columns([6, 1])
        with col1:
            user_input = st.text_input("Message LLM...", placeholder="Ask me anything about LLM...", label_visibility="collapsed")
        with col2:
            submit_button = st.form_submit_button("Send")

        if submit_button and user_input:
             # Just append messages visually for demo
             st.markdown(f'<div class="user-msg">{user_input}</div>', unsafe_allow_html=True)
             st.markdown('<div class="bot-msg">I am a demo bot. I received your message!</div>', unsafe_allow_html=True)


# --- Main App Logic ---

token = st.session_state.get('jwt_token')
if token:
    if verify_token(token):
        dashboard_page()
    else:
        st.session_state['jwt_token'] = None
        st.session_state['page'] = 'login'
        st.rerun()
else:
    if st.session_state['page'] == 'signup':
        signup_page()
    elif st.session_state['page'] == 'forgot':
        forgot_password_page()
    else:
        login_page()
