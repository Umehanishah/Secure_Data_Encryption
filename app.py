import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac

# Constants
DATA_FILE = "data.json"
KEY = Fernet.generate_key()
cipher = Fernet(KEY)
FAILED_ATTEMPTS_LIMIT = 3
LOCKOUT_TIME = 60  # seconds

# Load and save user data
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

# Encryption helpers
def hash_passkey(passkey, salt="static_salt"):
    return pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000).hex()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# Load state
if "users" not in st.session_state:
    st.session_state.users = load_data()

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "current_user" not in st.session_state:
    st.session_state.current_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "locked_until" not in st.session_state:
    st.session_state.locked_until = 0

# Page setup
st.set_page_config(page_title="Secure Data System", page_icon="🔒")
st.title("🔐 Secure Data Encryption System")

# Registration page
if not st.session_state.logged_in and st.session_state.current_user is None:
    st.subheader("📝 Register New User")
    reg_username = st.text_input("Create Username")
    reg_userid = st.text_input("Create User ID")
    reg_passkey = st.text_input("Set Passkey", type="password")

    if st.button("Register"):
        if reg_username and reg_userid and reg_passkey:
            user_key = f"{reg_username}:{reg_userid}"
            if user_key in st.session_state.users:
                st.warning("⚠️ User already exists!")
            else:
                st.session_state.users[user_key] = {
                    "passkey": hash_passkey(reg_passkey),
                    "data": ""
                }
                save_data(st.session_state.users)
                st.success("✅ Registered successfully! Now login below 👇")
        else:
            st.error("❌ All fields are required to register.")

# Login page
if not st.session_state.logged_in:
    st.markdown("---")
    st.subheader("🔑 Login to Continue")
    login_username = st.text_input("Username")
    login_userid = st.text_input("User ID")
    login_passkey = st.text_input("Passkey", type="password")

    if st.button("Login"):
        user_key = f"{login_username}:{login_userid}"
        user_record = st.session_state.users.get(user_key)

        if not user_record:
            st.error("❌ User not found.")
        elif user_record["passkey"] != hash_passkey(login_passkey):
            st.session_state.failed_attempts += 1
            attempts_left = FAILED_ATTEMPTS_LIMIT - st.session_state.failed_attempts
            st.error(f"❌ Incorrect passkey. Attempts left: {attempts_left}")

            if st.session_state.failed_attempts >= FAILED_ATTEMPTS_LIMIT:
                st.session_state.locked_until = time.time() + LOCKOUT_TIME
                st.warning("🔒 Too many failed attempts. Try again later.")
        else:
            st.session_state.logged_in = True
            st.session_state.current_user = user_key
            st.session_state.failed_attempts = 0
            st.success("✅ Login successful!")

# Main interface after login
if st.session_state.logged_in and st.session_state.current_user:
    st.sidebar.success("✅ Logged in")
    st.sidebar.button("🚪 Logout", on_click=lambda: [
        st.session_state.update({"logged_in": False, "current_user": None})
    ])
    
    menu = st.sidebar.radio("📁 Menu", ["Home", "Store Data", "Retrieve Data"])

    if menu == "Home":
        st.info("Welcome! You can now store or retrieve your encrypted data.")
    
    elif menu == "Store Data":
        st.subheader("📂 Store Encrypted Data")
        user_data = st.text_area("Enter text to encrypt and store:")

        if st.button("Encrypt & Save"):
            encrypted = encrypt_data(user_data)
            st.session_state.users[st.session_state.current_user]["data"] = encrypted
            save_data(st.session_state.users)
            st.success("✅ Your data has been securely encrypted and saved!")

    elif menu == "Retrieve Data":
        st.subheader("🔎 Retrieve Your Data")
        confirm_passkey = st.text_input("Confirm your passkey to decrypt:", type="password")

        if time.time() < st.session_state.locked_until:
            st.error("🔐 Locked out temporarily due to failed attempts.")
        elif st.button("Decrypt & View"):
            user_record = st.session_state.users.get(st.session_state.current_user)

            if user_record["passkey"] != hash_passkey(confirm_passkey):
                st.session_state.failed_attempts += 1
                attempts_left = FAILED_ATTEMPTS_LIMIT - st.session_state.failed_attempts
                st.error(f"❌ Wrong passkey. Attempts left: {attempts_left}")

                if st.session_state.failed_attempts >= FAILED_ATTEMPTS_LIMIT:
                    st.session_state.locked_until = time.time() + LOCKOUT_TIME
                    st.warning("🔒 Locked out due to too many failed attempts.")
            else:
                st.session_state.failed_attempts = 0
                encrypted_data = user_record.get("data", "")
                if encrypted_data:
                    decrypted = decrypt_data(encrypted_data)
                    st.success(f"✅ Your data:\n\n{decrypted}")
                else:
                    st.info("📭 No data saved yet.")
