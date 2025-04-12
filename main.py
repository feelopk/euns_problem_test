import streamlit as st
import sqlite3
import os
from datetime import datetime
import hashlib
import streamlit.components.v1 as components

# ------------------------------------------------------------------------------
# 데이터베이스 초기화
# ------------------------------------------------------------------------------

def init_db():
    # SQLite 데이터베이스에 연결(또는 새로 생성)
    conn = sqlite3.connect("assignment.db", check_same_thread=False)
    c = conn.cursor()
    # 사용자 정보를 저장하기 위한 테이블 생성 (존재하지 않을 경우)
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    # 학생들의 제출 기록을 저장하기 위한 테이블 생성
    c.execute('''
        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            submission_time TEXT,
            answers TEXT,
            score INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    return conn

conn = init_db()

# ------------------------------------------------------------------------------
# 인증 관련 유틸리티 함수들
# ------------------------------------------------------------------------------

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register(username, password):
    try:
        conn.execute("INSERT INTO users(username, password) VALUES(?, ?)",
                     (username, hash_password(password)))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def login(username, password):
    user = conn.execute("SELECT * FROM users WHERE username = ? AND password = ?",
                        (username, hash_password(password))).fetchone()
    return user

# ------------------------------------------------------------------------------
# 세션 상태 및 인증 UI
# ------------------------------------------------------------------------------

# 로그인 상태를 저장하는 session state 초기화
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user = None

st.sidebar.title("사용자 인증")
auth_choice = st.sidebar.selectbox("옵션 선택", ["로그인", "회원가입"])

if auth_choice == "회원가입":
    st.sidebar.subheader("새 계정 생성")
    new_username = st.sidebar.text_input("아이디", key="signup_username")
    new_password = st.sidebar.text_input("비밀번호", type="password", key="signup_password")
    if st.sidebar.button("회원가입"):
        if register(new_username, new_password):
            st.sidebar.success("계정 생성 완료! 로그인 해주세요.")
        else:
            st.sidebar.error("이미 존재하는 아이디입니다. 다른 아이디를 사용해보세요.")
else:
    st.sidebar.subheader("로그인")
    username = st.sidebar.text_input("아이디", key="login_username")
    password = st.sidebar.text_input("비밀번호", type="password", key="login_password")
    if st.sidebar.button("로그인"):
        user = login(username, password)
        if user:
            st.session_state.logged_in = True
            st.session_state.user = user
            st.sidebar.success("정상적으로 로그인되었습니다!")
        else:
            st.sidebar.error("로그인 실패. 아이디와 비밀번호를 확인하세요.")

# ------------------------------------------------------------------------------
# 메인 앱: 과제 제출
# ------------------------------------------------------------------------------

if st.session_state.logged_in:
    st.header("과제 제출")
    st.write(f"{st.session_state.user[1]} 님, 환영합니다!")
    st.write("아래에서 과제 내용을 확인하고 제출해주세요.")

    # 과제 HTML 양식을 임베디드 컴포넌트로 표시
    html_file = "index_fine.html"
    if os.path.exists(html_file):
        with open(html_file, "r", encoding="utf-8") as f:
            html_code = f.read()
        components.html(html_code, height=1000, scrolling=True)
    else:
        st.error("과제 파일을 찾을 수 없습니다.")

    # 선택 사항: 제출 버튼을 추가할 수 있습니다.
    # 주의: HTML 양식에서 별도로 제출이 처리되는 경우, 여기서는 더미 제출 기능을 구현합니다.
    if st.button("과제 제출"):
        submission_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # 실제 제출 시에는 폼에서 받은 응답과 점수를 사용하여 계산해야 합니다.
        dummy_answers = "HTML 양식을 통해 제출됨."
        dummy_score = 0  # 논리에 따라 실제 점수를 계산하세요.
        user_id = st.session_state.user[0]
        conn.execute(
            "INSERT INTO submissions (user_id, submission_time, answers, score) VALUES (?, ?, ?, ?)",
            (user_id, submission_time, dummy_answers, dummy_score)
        )
        conn.commit()
        st.success("과제가 성공적으로 제출되었습니다!")
else:
    st.write("좌측 사이드바에서 로그인 후 과제 제출 페이지에 접근할 수 있습니다.")
