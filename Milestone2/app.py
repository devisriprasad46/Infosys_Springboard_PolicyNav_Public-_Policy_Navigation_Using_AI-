import streamlit as st
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import jwt
import datetime
import time
import os
import re
import hmac
import hashlib
import struct
import secrets
import textstat
from plotly import graph_objects as go
import PyPDF2
import db

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS", "devisriprasad2090@gmail.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
SECRET_KEY = os.getenv("JWT_SECRET", "super_secret_key_for_demo")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
OTP_EXPIRY_MINUTES = 10
USE_OTP = False

if 'users_initialized' not in st.session_state:
    db.init_db()
    st.session_state['users_initialized'] = True

st.set_page_config(page_title='Public Policy Navigation using AI', page_icon='🤖', layout='wide')
st.markdown('''
    <style>
        .stApp { background-color: #0E1117; }
        h1 { text-align: center; color: #4F8BF9; font-family: 'Inter', sans-serif; margin-bottom: 0.5rem; }
        h3 { text-align: center; color: #FAFAFA; font-weight: 300; margin-top: 0; font-size: 1.2rem; }
        .stButton>button { width: 100%; border-radius: 8px; height: 3em; background-color: #4F8BF9; color: white; font-weight: bold; border: none; }
        .stButton>button:hover { background-color: #3b6ccf; }
        div[data-testid=stSidebar] { background-color: #262730; }
        .user-msg { text-align: right; background-color: #262730; color: white; padding: 10px; border-radius: 10px; margin: 5px; display: inline-block; max-width: 80%; float: right; clear: both; }
        .bot-msg { text-align: left; background-color: #4F8BF9; color: white; padding: 10px; border-radius: 10px; margin: 5px; display: inline-block; max-width: 80%; float: left; clear: both; }
    </style>
''', unsafe_allow_html=True)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        return None

def is_valid_email(email):
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None

def is_valid_password(password):
    if len(password) < 8:
        return False
    if any(ch.isspace() for ch in password):
        return False
    has_letter = any(ch.isalpha() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    return has_letter and has_digit

def generate_otp():
    secret = secrets.token_bytes(20)
    counter = int(time.time())
    msg = struct.pack(">Q", counter)
    h = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = h[19] & 0xf
    code = ((h[offset] & 0x7f) << 24 | (h[offset + 1] & 0xff) << 16 | (h[offset + 2] & 0xff) << 8 | (h[offset + 3] & 0xff))
    otp = code % 1000000
    return f"{otp:06d}"

def create_gauge(value, title, min_val, max_val, color):
    fig = go.Figure(go.Indicator(mode="gauge+number", value=value, title={'text': title, 'font': {'color': color, 'size': 14}}, number={'font': {'color': color, 'size': 20}}, gauge={'axis': {'range': [min_val, max_val], 'tickwidth': 1, 'tickcolor': color}, 'bar': {'color': color}, 'bgcolor': "#1f2937", 'borderwidth': 2, 'bordercolor': "#374151", 'steps': [{'range': [min_val, max_val], 'color': "#0e1117"}]}))
    fig.update_layout(paper_bgcolor="#0e1117", font={'color': "#ffffff", 'family': "Courier New"}, height=250, margin=dict(l=10, r=10, t=40, b=10))
    return fig

def readability_metrics(text):
    return {
        "Flesch Reading Ease": float(textstat.flesch_reading_ease(text)),
        "Flesch-Kincaid Grade": float(textstat.flesch_kincaid_grade(text)),
        "SMOG Index": float(textstat.smog_index(text)),
        "Gunning Fog": float(textstat.gunning_fog(text)),
        "Coleman-Liau": float(textstat.coleman_liau_index(text))
    }

def create_otp_token(otp, email):
    import bcrypt
    otp_hash = bcrypt.hashpw(otp.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    payload = {
        'otp_hash': otp_hash,
        'sub': email,
        'type': 'password_reset',
        'iat': datetime.datetime.utcnow(),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=OTP_EXPIRY_MINUTES)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_otp_token(token, input_otp, email):
    import bcrypt
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        if payload.get('sub') != email:
            return False, 'Token mismatch'
        if bcrypt.checkpw(input_otp.encode('utf-8'), payload['otp_hash'].encode('utf-8')):
            return True, 'Valid'
        return False, 'Invalid OTP'
    except Exception as e:
        return False, str(e)

def send_email(to_email, otp, app_pass):
    msg = MIMEMultipart()
    msg['From'] = f"Infosys LLM <{EMAIL_ADDRESS}>"
    msg['To'] = to_email
    msg['Subject'] = "Infosys LLM - Password Reset OTP"
    body = f"""
    <!DOCTYPE html>
    <html><body>
    <div>Use this OTP to reset your password for {to_email}.</div>
    <h2>{otp}</h2>
    <div>Valid for {OTP_EXPIRY_MINUTES} minutes.</div>
    </body></html>
    """
    msg.attach(MIMEText(body, 'html'))
    try:
        s = smtplib.SMTP('smtp.gmail.com', 587)
        s.starttls()
        s.login(EMAIL_ADDRESS, app_pass if app_pass else EMAIL_PASSWORD)
        s.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())
        s.quit()
        return True, "Sent"
    except Exception as e:
        return False, str(e)

if 'jwt_token' not in st.session_state:
    st.session_state['jwt_token'] = None
if 'page' not in st.session_state:
    st.session_state['page'] = 'login'

def login_page():
    st.markdown("<br>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.title("Public Policy Navigation using AI")
        st.markdown("<h3>Please sign in to continue</h3>", unsafe_allow_html=True)
        with st.form("login_form"):
            email = st.text_input("Email Address")
            password = st.text_input("Password", type='password')
            submitted = st.form_submit_button("Sign In")
            if submitted:
                if not email and not password:
                    st.error("Email and Password are mandatory.")
                elif not email:
                    st.error("Email should be entered.")
                elif not password:
                    st.error("Password should be entered.")
                else:
                    locked, wait = db.is_rate_limited(email)
                    if locked:
                        st.error(f"Account locked. Try again in {int(wait)} seconds.")
                    else:
                        ok, uname = db.authenticate_user(email, password)
                        if ok:
                            token = create_access_token({"sub": email, "username": uname})
                            st.session_state['jwt_token'] = token
                            st.success("Login successful!")
                            time.sleep(0.5)
                            if email == "admin@llm.com":
                                st.session_state['page'] = 'admin'
                            else:
                                st.session_state['page'] = 'dashboard'
                            st.rerun()
                        else:
                            if db.check_password_reused(email, password):
                                st.error("You are using an old password. Enter the new changed password.")
                            else:
                                st.error("Invalid email or password")
        st.markdown("<div style=\"height: 12px\"></div>", unsafe_allow_html=True)
        c_left, c_right = st.columns([1, 1])
        with c_left:
            if st.button("Forgot Password?", use_container_width=True):
                st.session_state['page'] = 'forgot'
                st.rerun()
        with c_right:
            if st.button("Create an Account", use_container_width=True):
                st.session_state['page'] = 'signup'
                st.rerun()

def signup_page():
    st.markdown("<br>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.title("Create Account")
        with st.form("signup_form"):
            username = st.text_input("Username (Required)")
            email = st.text_input("Email Address (@domain.com required)")
            password = st.text_input("Password (min 8 chars; letters+digits; symbols allowed)", type='password')
            confirm_password = st.text_input("Confirm Password", type='password')
            security_question = st.selectbox("Security Question", [
                "What is your pet name?",
                "What is your mother’s maiden name?",
                "What is your favorite teacher?"
            ])
            security_answer = st.text_input("Security Answer")
            submitted = st.form_submit_button("Sign Up")
            if submitted:
                errors = []
                if not username:
                    errors.append("Username is mandatory.")
                elif db.username_exists(username):
                    errors.append(f"Username '{username}' is already taken.")
                if not email:
                    errors.append("Email is mandatory.")
                elif not is_valid_email(email):
                    errors.append("Invalid Email format (e.g. user@domain.com).")
                elif db.email_exists(email):
                    errors.append(f"Email '{email}' is already registered.")
                if not password:
                    errors.append("Password is mandatory.")
                elif not is_valid_password(password):
                    errors.append("Password must be 8+ chars, include letters and digits, no spaces.")
                if password != confirm_password:
                    errors.append("Passwords do not match.")
                if not security_answer or not security_answer.strip():
                    errors.append("Security Answer is mandatory.")
                if errors:
                    for error in errors:
                        st.error(error)
                else:
                    ok = db.register_user(email, username, password, security_question, security_answer.strip().lower())
                    if ok:
                        token = create_access_token({"sub": email, "username": username})
                        st.session_state['jwt_token'] = token
                        st.success("Account created successfully!")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error("Failed to create user. Email/Username may exist.")
    st.markdown("---")
    if st.button("Back to Login"):
        st.session_state['page'] = 'login'
        st.rerun()

def forgot_password_page():
    st.markdown("<br>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.title("Forgot Password")
        if 'stage' not in st.session_state:
            st.session_state['stage'] = 'email'
        stage = st.session_state['stage']
        if stage == 'email':
            email = st.text_input("Email *")
            c1, c2 = st.columns(2)
            if c1.button("Next"):
                if db.check_user_exists(email):
                    st.session_state['reset_email'] = email
                    st.session_state['stage'] = 'method'
                    st.rerun()
                else:
                    st.error("Email not found.")
            if c2.button("Back to Login"):
                st.session_state['page'] = 'login'
                st.rerun()
        elif stage == 'method':
            st.markdown("### Choose a verification method")
            c1, c2 = st.columns(2)
            if c1.button("Send OTP (Recommended)"):
                st.session_state['stage'] = 'otp'
                st.rerun()
            if c2.button("Try another way: Use Security Answer"):
                st.session_state['stage'] = 'security'
                st.rerun()
        elif stage == 'otp':
            st.info(f"Sending to {st.session_state.get('reset_email','')}")
            if st.button("Send OTP"):
                otp = generate_otp()
                ok, msg = send_email(st.session_state['reset_email'], otp, EMAIL_PASSWORD)
                if ok:
                    st.session_state['token'] = create_otp_token(otp, st.session_state['reset_email'])
                    st.session_state['stage'] = 'verify'
                    st.rerun()
                else:
                    st.error(msg)
        elif stage == 'security':
            email = st.session_state.get('reset_email','')
            row = db.get_user_by_email(email)
            q = row['sec_q'] if row else ''
            st.text_input('Security Question', value=q, disabled=True)
            ans = st.text_input('Security Answer')
            if st.button('Verify Answer'):
                if not ans or not ans.strip():
                    st.error('Security Answer is required.')
                elif not row or ans.strip().lower() != str(row['sec_a']).strip().lower():
                    st.error('Incorrect answer.')
                else:
                    st.session_state['stage'] = 'reset'
                    st.rerun()
        elif stage == 'verify':
            otp_in = st.text_input("Enter OTP *")
            if st.button("Verify"):
                ok, msg = verify_otp_token(st.session_state.get('token'), otp_in, st.session_state.get('reset_email',''))
                if ok:
                    st.session_state['stage'] = 'reset'
                    st.rerun()
                else:
                    st.error(msg)
        elif stage == 'reset':
            p1 = st.text_input("New Password *", type='password')
            p2 = st.text_input("Confirm *", type='password')
            if st.button("Update"):
                if p1 != p2:
                    st.error("Passwords do not match.")
                elif db.check_password_reused(st.session_state.get('reset_email',''), p1):
                    st.error("Cannot reuse old password")
                elif not is_valid_password(p1):
                    st.error("Password must be 8+ chars, include letters and digits, no spaces.")
                else:
                    db.update_password(st.session_state.get('reset_email',''), p1)
                    st.success("Password updated successfully.")
                    time.sleep(1)
                    st.session_state['page'] = 'login'
                    st.rerun()

def admin_page():
    st.sidebar.title('🛡️ Admin Panel')
    if st.sidebar.button('Logout'):
        st.session_state['jwt_token'] = None
        st.session_state['page'] = 'login'
        st.rerun()
    st.title('👥 User Management')
    users = db.get_all_users()
    for u_email, u_created in users:
        c1, c2, c3 = st.columns([3, 2, 1])
        c1.write(f"**{u_email}**")
        c2.write(u_created or '')
        if u_email != 'admin@llm.com':
            if c3.button('Delete', key=u_email):
                db.delete_user(u_email)
                st.warning(f'Deleted {u_email}')
                time.sleep(0.5)
                st.rerun()

def dashboard_page():
    token = st.session_state.get('jwt_token')
    payload = verify_token(token)
    if not payload:
        st.session_state['jwt_token'] = None
        st.warning('Session expired or invalid. Please login again.')
        time.sleep(1)
        st.rerun()
        return
    username = payload.get('username', 'User')
    if 'dashboard_view' not in st.session_state:
        st.session_state['dashboard_view'] = 'chat'
    with st.sidebar:
        st.title('🤖 LLM')
        st.markdown('---')
        c1, c2 = st.columns(2)
        with c1:
            if st.button('➕ New Chat', use_container_width=True):
                st.session_state['dashboard_view'] = 'chat'
                st.info('Started new chat!')
        with c2:
            if st.button('📖 Readability', use_container_width=True):
                st.session_state['dashboard_view'] = 'readability'
        st.markdown('### History')
        st.markdown('- Project analysis')
        st.markdown('- NLP')
        st.markdown('---')
        st.markdown('### Settings')
        if st.button('Logout', use_container_width=True):
            st.session_state['jwt_token'] = None
            st.rerun()
    if st.session_state['dashboard_view'] == 'readability':
        st.title('Text Readability Analyzer')
        tab1, tab2 = st.tabs(['Input Text', 'Upload File'])
        text_input = ''
        with tab1:
            raw_text = st.text_area('Enter text to analyze (min 50 chars):', height=200)
            if raw_text:
                text_input = raw_text
        with tab2:
            uploaded_file = st.file_uploader('Upload a file', type=['txt','pdf'])
            if uploaded_file:
                try:
                    if uploaded_file.type == 'application/pdf':
                        reader = PyPDF2.PdfReader(uploaded_file)
                        txt = ''
                        for page in reader.pages:
                            page_text = page.extract_text() or ''
                            txt += page_text + '\n'
                        text_input = txt
                    else:
                        text_input = uploaded_file.read().decode('utf-8')
                except Exception as e:
                    st.error(str(e))
        if st.button('Analyze Readability'):
            if len(text_input) < 50:
                st.error('Text is too short (min 50 chars).')
            else:
                import readability
                analyzer = readability.ReadabilityAnalyzer(text_input)
                score = analyzer.get_all_metrics()
                st.markdown('---')
                st.subheader('📊 Analysis Results')
                avg_grade = (score['Flesch-Kincaid Grade'] + score['Gunning Fog'] + score['SMOG Index'] + score['Coleman-Liau']) / 4.0
                if avg_grade <= 6:
                    level, color = 'Beginner', '#28a745'
                elif avg_grade <= 10:
                    level, color = 'Intermediate', '#17a2b8'
                elif avg_grade <= 14:
                    level, color = 'Advanced', '#ffc107'
                else:
                    level, color = 'Expert', '#dc3545'
                st.markdown(f"<div style='background-color:#1f2937;padding:20px;border-radius:10px;border-left:5px solid {color};text-align:center;'><h2 style='margin:0;color:{color}'>Overall Level: {level}</h2><p style='margin:5px 0 0 0;color:#9ca3af'>Approximate Grade Level: {int(avg_grade)}</p></div>", unsafe_allow_html=True)
                st.markdown('### 📈 Detailed Metrics')
                c1, c2, c3 = st.columns(3)
                with c1:
                    st.plotly_chart(create_gauge(score['Flesch Reading Ease'], 'Flesch Reading Ease', 0, 100, '#00ffcc'), use_container_width=True)
                    with st.expander('ℹ️ About Flesch Ease'):
                        st.caption('0-100 Scale. Higher is easier. 60-70 is standard.')
                with c2:
                    st.plotly_chart(create_gauge(score['Flesch-Kincaid Grade'], 'Flesch-Kincaid Grade', 0, 20, '#ff00ff'), use_container_width=True)
                    with st.expander('ℹ️ About Kincaid Grade'):
                        st.caption('US Grade Level. 8.0 means 8th grader can understand.')
                with c3:
                    st.plotly_chart(create_gauge(score['SMOG Index'], 'SMOG Index', 0, 20, '#ffa500'), use_container_width=True)
                    with st.expander('ℹ️ About SMOG'):
                        st.caption('Commonly used for medical writing. Based on polysyllables.')
                c4, c5 = st.columns(2)
                with c4:
                    st.plotly_chart(create_gauge(score['Gunning Fog'], 'Gunning Fog', 0, 20, '#4F8BF9'), use_container_width=True)
                    with st.expander('ℹ️ About Gunning Fog'):
                        st.caption('Based on sentence length and complex words.')
                with c5:
                    st.plotly_chart(create_gauge(score['Coleman-Liau'], 'Coleman-Liau', 0, 20, '#34d399'), use_container_width=True)
                    with st.expander('ℹ️ About Coleman-Liau'):
                        st.caption('Based on characters instead of syllables. Good for automated analysis.')
                st.markdown('### 📝 Text Statistics')
                s1, s2, s3, s4, s5 = st.columns(5)
                s1.metric('Sentences', analyzer.num_sentences)
                s2.metric('Words', analyzer.num_words)
                s3.metric('Syllables', analyzer.num_syllables)
                s4.metric('Complex Words', analyzer.complex_words)
                s5.metric('Characters', analyzer.char_count)
    else:
        st.title(f'Welcome, {username}!')
        st.markdown('### How can I help you today?')
        chat_placeholder = st.empty()
        with chat_placeholder.container():
            st.markdown('<div class="bot-msg">Hello! I am LLM. Ask me anything about LLM!</div>', unsafe_allow_html=True)
        with st.form(key='chat_form', clear_on_submit=True):
            col1, col2 = st.columns([6, 1])
            with col1:
                user_input = st.text_input('Message LLM...', placeholder='Ask me anything about LLM...', label_visibility='collapsed')
            with col2:
                submit_button = st.form_submit_button('Send')
            if submit_button and user_input:
                st.markdown(f"<div class='user-msg'>{user_input}</div>", unsafe_allow_html=True)
                st.markdown('<div class="bot-msg">I am a demo bot. I received your message!</div>', unsafe_allow_html=True)

token = st.session_state.get('jwt_token')
if token:
    if verify_token(token):
        if st.session_state.get('page') == 'admin':
            admin_page()
        else:
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
