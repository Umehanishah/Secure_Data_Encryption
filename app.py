import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import base64
import os

# In-memory storage for user data
stored_data = {}

# Function to generate a Fernet key from a passkey
def generate_key(passkey):
    # Hash the passkey using SHA-256
    digest = hashlib.sha256(passkey.encode()).digest()
    # Encode the hash in URL-safe base64
    return base64.urlsafe_b64encode(digest)

# Function to encrypt data using the passkey
def encrypt_data(data, passkey):
    key = generate_key(passkey)
    fernet = Fernet(key)
    return fernet.encrypt(data.encode()).decode()

# Function to decrypt data using the passkey
def decrypt_data(encrypted_data, passkey):
    key = generate_key(passkey)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data.encode()).decode()

# Initialize session state variables
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'attempts' not in st.session_state:
    st.session_state.attempts = 0
if 'current_user' not in st.session_state:
    st.session_state.current_user = None

# Page configuration
st.set_page_config(page_title="🔐 Secure Data Encryption", page_icon="🔐", layout="centered")

# Title
st.markdown("""
    # 🔐 Secure Data Encryption System
    ### Store and retrieve your data securely with a unique passkey.
""")

# Login function
def login():
    st.session_state.authenticated = False
    st.session_state.attempts = 0
    st.session_state.current_user = None
    st.success("🔓 Logged out successfully.")

# Logout button
if st.session_state.authenticated:
    if st.button("🔒 Logout"):
        login()

# Authentication
if not st.session_state.authenticated:
    st.subheader("🔑 Login")
    username = st.text_input("Username")
    passkey = st.text_input("Passkey", type="password")
    if st.button("Login"):
        if username in stored_data:
            hashed_passkey = hashlib.sha256(passkey.encode()).hexdigest()
            if stored_data[username]['passkey'] == hashed_passkey:
                st.session_state.authenticated = True
                st.session_state.current_user = username
                st.success("✅ Logged in successfully.")
            else:
                st.session_state.attempts += 1
                st.error(f"❌ Incorrect passkey. Attempt {st.session_state.attempts}/3.")
                if st.session_state.attempts >= 3:
                    st.warning("⚠️ Too many failed attempts. Please try again later.")
        else:
            st.error("❌ Username not found.")
else:
    st.subheader(f"Welcome, {st.session_state.current_user}!")

    # Data encryption
    st.markdown("### 🔐 Encrypt Data")
    data_to_encrypt = st.text_area("Enter data to encrypt")
    encryption_passkey = st.text_input("Enter a new passkey", type="password")
    if st.button("Encrypt and Store"):
        if data_to_encrypt and encryption_passkey:
            encrypted_text = encrypt_data(data_to_encrypt, encryption_passkey)
            hashed_passkey = hashlib.sha256(encryption_passkey.encode()).hexdigest()
            stored_data[st.session_state.current_user] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data encrypted and stored successfully.")
        else:
            st.error("❌ Please provide both data and a passkey.")

    # Data decryption
    st.markdown("### 🔓 Decrypt Data")
    decryption_passkey = st.text_input("Enter your passkey to decrypt data", type="password")
    if st.button("Decrypt"):
        if st.session_state.current_user in stored_data:
            try:
                decrypted_text = decrypt_data(
                    stored_data[st.session_state.current_user]['encrypted_text'],
                    decryption_passkey
                )
                st.success("✅ Data decrypted successfully:")
                st.code(decrypted_text)
            except Exception as e:
                st.session_state.attempts += 1
                st.error(f"❌ Decryption failed. Attempt {st.session_state.attempts}/3.")
                if st.session_state.attempts >= 3:
                    st.warning("⚠️ Too many failed attempts. Logging out.")
                    login()
        else:
            st.error("❌ No data found for decryption.")
