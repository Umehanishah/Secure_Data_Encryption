import streamlit as st # type: ignore
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet # type: ignore
from hashlib import pbkdf2_hmac

# Constants
DATA_FILE = "data.json"
KEY = Fernet.generate_key()
cipher = Fernet(KEY)
FAILED_ATTEMPTS_LIMIT = 3
LOCKOUT_TIME = 60  # seconds


def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}


def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)


def hash_passkey(passkey, salt="static_salt"):
    return pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000).hex()


def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()


def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()


if "users" not in st.session_state:
    st.session_state.users = load_data()

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "locked_until" not in st.session_state:
    st.session_state.locked_until = 0

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "current_user" not in st.session_state:
    st.session_state.current_user = None


st.set_page_config(page_title="Secure Data System", page_icon="🔒")
st.title("🔐 Secure Data Encryption System")


if not st.session_state.logged_in:
    st.subheader("🔑 Please Log In")
    username = st.text_input("Username:")
    userid = st.text_input("User ID:")
    passkey = st.text_input("Passkey:", type="password")

    if st.button("Login"):
        user_key = f"{username}:{userid}"
        user_record = st.session_state.users.get(user_key)

        if not user_record:
            st.error("❌ User not found.")
        elif user_record["passkey"] != hash_passkey(passkey):
            st.error("❌ Incorrect passkey.")
        else:
            st.session_state.logged_in = True
            st.session_state.current_user = user_key
            st.success("✅ Login successful! Use the sidebar to navigate.")
else:
   
    st.sidebar.title("🔐 Navigation")
    menu = st.sidebar.radio("Go to", ["Home", "Register", "Store Data", "Retrieve Data", "Logout"])

    if menu == "Logout":
        st.session_state.logged_in = False
        st.session_state.current_user = None
        st.success("✅ Logged out successfully.")
        st.experimental_rerun()

    elif menu == "Home":
        st.markdown("### Welcome Back!")
        st.info("Use this app to securely store and retrieve personal data using passkeys.")

    elif menu == "Register":
        st.subheader("🆕 User Registration")
        new_username = st.text_input("Enter Username:")
        new_userid = st.text_input("Enter User ID:")
        new_passkey = st.text_input("Set Passkey:", type="password")

        if st.button("Register"):
            if new_username and new_userid and new_passkey:
                new_key = f"{new_username}:{new_userid}"
                if new_key in st.session_state.users:
                    st.warning("⚠️ User already exists!")
                else:
                    st.session_state.users[new_key] = {
                        "passkey": hash_passkey(new_passkey),
                        "data": ""
                    }
                    save_data(st.session_state.users)
                    st.success("✅ User registered successfully!")
            else:
                st.error("❌ All fields are required!")

    elif menu == "Store Data":
        st.subheader("📂 Store Data")
        user_data = st.text_area("Enter data to encrypt:")

        if st.button("Encrypt & Store"):
            user_key = st.session_state.current_user
            if user_key:
                encrypted = encrypt_data(user_data)
                st.session_state.users[user_key]["data"] = encrypted
                save_data(st.session_state.users)
                st.success("✅ Data encrypted and stored!")
            else:
                st.error("❌ Login session not found.")

    elif menu == "Retrieve Data":
        st.subheader("🔎 Retrieve Data")
        if time.time() < st.session_state.locked_until:
            st.error("🔐 Locked due to multiple failed attempts. Try again later.")
        else:
            passkey = st.text_input("Confirm Passkey:", type="password")

            if st.button("Retrieve"):
                user_key = st.session_state.current_user
                user_record = st.session_state.users.get(user_key)

                if not user_record:
                    st.error("❌ User not found.")
                elif user_record["passkey"] != hash_passkey(passkey):
                    st.session_state.failed_attempts += 1
                    attempts_left = FAILED_ATTEMPTS_LIMIT - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")

                    if st.session_state.failed_attempts >= FAILED_ATTEMPTS_LIMIT:
                        st.session_state.locked_until = time.time() + LOCKOUT_TIME
                        st.warning("🔒 Too many failed attempts. Locked out temporarily.")
                else:
                    st.session_state.failed_attempts = 0
                    encrypted_data = user_record.get("data")
                    if encrypted_data:
                        decrypted = decrypt_data(encrypted_data)
                        st.success(f"✅ Decrypted Data:\n\n{decrypted}")
                    else:
                        st.info("📭 No data found for this user.")
