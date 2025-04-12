import streamlit as st
import hashlib
import time
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac

# Constants
KEY = Fernet.generate_key()  # In production, store securely
cipher = Fernet(KEY)
FAILED_ATTEMPTS_LIMIT = 3
LOCKOUT_TIME = 60  # seconds

# Session Initialization
if "users" not in st.session_state:
    st.session_state.users = {}

if "current_user" not in st.session_state:
    st.session_state.current_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "locked_until" not in st.session_state:
    st.session_state.locked_until = 0

# Functions
def hash_passkey(passkey, salt="mysalt"):
    return pbkdf2_hmac("sha256", passkey.encode(), salt.encode(), 100000).hex()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# UI Layout
st.set_page_config(page_title="🔐 Secure System", page_icon="🔐")
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data", "Logout"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home Page
if choice == "Home":
    st.header("🏠 Home")
    st.markdown("A secure system to **store** and **retrieve** encrypted data using passkeys.")
    if st.session_state.current_user:
        st.success(f"✅ Logged in as: `{st.session_state.current_user}`")
    else:
        st.info("🔒 You are not logged in.")

# Register Page
elif choice == "Register":
    st.header("📝 Register")
    username = st.text_input("Choose a Username")
    passkey = st.text_input("Set a Passkey", type="password")

    if st.button("Register"):
        if username and passkey:
            if username in st.session_state.users:
                st.warning("⚠️ Username already exists.")
            else:
                st.session_state.users[username] = {
                    "passkey": hash_passkey(passkey),
                    "data": ""
                }
                st.success("✅ Registration successful!")
        else:
            st.error("❌ All fields are required!")

# Login Page
elif choice == "Login":
    st.header("🔐 Login")
    username = st.text_input("Username")
    passkey = st.text_input("Passkey", type="password")

    if st.button("Login"):
        user = st.session_state.users.get(username)
        if user and user["passkey"] == hash_passkey(passkey):
            st.session_state.current_user = username
            st.session_state.failed_attempts = 0
            st.success("✅ Logged in successfully!")
        else:
            st.error("❌ Invalid username or passkey")

# Store Data Page
elif choice == "Store Data":
    if not st.session_state.current_user:
        st.warning("⚠️ Please log in first.")
    else:
        st.header("📂 Store Encrypted Data")
        plain_text = st.text_area("Enter Data to Encrypt:")

        if st.button("Encrypt & Store"):
            if plain_text:
                encrypted = encrypt_data(plain_text)
                st.session_state.users[st.session_state.current_user]["data"] = encrypted
                st.success("✅ Data encrypted and stored!")
            else:
                st.error("❌ Data field cannot be empty.")

# Retrieve Data Page
elif choice == "Retrieve Data":
    if not st.session_state.current_user:
        st.warning("⚠️ Please log in first.")
    elif time.time() < st.session_state.locked_until:
        st.error("🔐 Too many failed attempts. Try again later.")
    else:
        st.header("🔍 Retrieve Your Data")
        passkey = st.text_input("Enter Your Passkey", type="password")

        if st.button("Decrypt Data"):
            stored = st.session_state.users[st.session_state.current_user]["data"]
            expected_hash = st.session_state.users[st.session_state.current_user]["passkey"]

            if hash_passkey(passkey) == expected_hash:
                if stored:
                    decrypted = decrypt_data(stored)
                    st.success(f"✅ Decrypted Data:\n\n{decrypted}")
                    st.session_state.failed_attempts = 0
                else:
                    st.info("📭 No data stored yet.")
            else:
                st.session_state.failed_attempts += 1
                remaining = FAILED_ATTEMPTS_LIMIT - st.session_state.failed_attempts
                st.error(f"❌ Wrong passkey! Attempts left: {remaining}")

                if st.session_state.failed_attempts >= FAILED_ATTEMPTS_LIMIT:
                    st.session_state.locked_until = time.time() + LOCKOUT_TIME
                    st.warning("🔒 Locked due to multiple failed attempts. Try again in 60 seconds.")

# Logout Page
elif choice == "Logout":
    st.session_state.current_user = None
    st.success("✅ You have been logged out.")
