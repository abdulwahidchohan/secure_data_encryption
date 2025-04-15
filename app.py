import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import time

# Initialize session state with emoji-prefixed pages
if 'page' not in st.session_state:
    st.session_state.page = "🏠 Home"
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'cipher' not in st.session_state:
    KEY = Fernet.generate_key()
    st.session_state.cipher = Fernet(KEY)
if 'next_id' not in st.session_state:
    st.session_state.next_id = 1
if 'clear_all' not in st.session_state:
    st.session_state.clear_all = False

# Utility Functions
def hash_passkey(passkey):
    """Hash the passkey using SHA-256."""
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    """Encrypt the provided text."""
    return st.session_state.cipher.encrypt(text.encode()).decode()

def decrypt_data(id, passkey):
    """Decrypt data if the passkey matches."""
    item = st.session_state.stored_data.get(id)
    if item and hash_passkey(passkey) == item["passkey"]:
        st.session_state.failed_attempts = 0
        return st.session_state.cipher.decrypt(item["encrypted_text"].encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

# Main UI
st.title("🔒 Secure Data Encryption System")

# Sidebar Navigation
menu = ["🏠 Home", "📂 Store Data", "🔍 Retrieve Data", "🗃️ Manage Data", "🔑 Login"]
if st.session_state.page not in menu:
    st.session_state.page = menu[0]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.page))
st.session_state.page = choice

# Home Page
if st.session_state.page == "🏠 Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Easily store and retrieve encrypted data with this secure app!")
    st.markdown("""
    - **Store Data**: Save your data with a unique label and passkey.  
    - **Retrieve Data**: Access your data by selecting its label and entering the passkey.  
    - **Manage Data**: View or delete your stored entries.  
    **Note**: Data is stored in memory and lost on app restart.
    """)
    with st.expander("ℹ️ How It Works"):
        st.write("Data is encrypted using Fernet encryption and stored with a hashed passkey for security.")

# Store Data Page
elif st.session_state.page == "📂 Store Data":
    st.subheader("📂 Store Data Securely")
    label = st.text_input("Enter Label for Data:", help="A name to identify your data.")
    user_data = st.text_area("Enter Data:", help="The information you want to encrypt.")
    passkey = st.text_input("Enter Passkey (min 8 characters):", type="password", help="Keep this secret!")

    if st.button("Encrypt & Save"):
        if label and passkey and len(passkey) >= 8:
            id = str(st.session_state.next_id)
            st.session_state.next_id += 1
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            st.session_state.stored_data[id] = {
                "label": label,
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success(f"✅ Data stored securely with label '{label}'!")
        else:
            st.error("⚠️ Label and passkey are required, and passkey must be at least 8 characters.")

# Retrieve Data Page
elif st.session_state.page == "🔍 Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    if st.session_state.stored_data:
        selected_id = st.selectbox(
            "Select Data Label",
            options=list(st.session_state.stored_data.keys()),
            format_func=lambda x: st.session_state.stored_data[x]["label"],
            help="Choose the data to decrypt."
        )
        passkey = st.text_input("Enter Passkey:", type="password", help="The passkey used to encrypt this data.")

        if st.button("Decrypt"):
            if passkey:
                with st.spinner("Decrypting..."):
                    time.sleep(0.5)  # Simulate processing
                    decrypted_text = decrypt_data(selected_id, passkey)
                if decrypted_text:
                    st.success(f"✅ Decrypted Data: {decrypted_text}")
                else:
                    attempts_left = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")
                    if st.session_state.failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts! Redirecting to Login...")
                        time.sleep(1)
                        st.session_state.page = "🔑 Login"
                        st.rerun()
            else:
                st.error("⚠️ Passkey is required!")
    else:
        st.info("📭 No data stored yet. Visit 'Store Data' to add some.")
    with st.expander("ℹ️ Forgot Your Passkey?"):
        st.write("For this demo, there’s no recovery option. Use the correct passkey or store new data.")

# Manage Data Page
elif st.session_state.page == "🗃️ Manage Data":
    st.subheader("🗃️ Manage Stored Data")
    if st.session_state.stored_data:
        for id, item in list(st.session_state.stored_data.items()):
            col1, col2 = st.columns([3, 1])
            col1.write(f"Label: {item['label']}")
            if col2.button("Delete", key=f"delete_{id}"):
                del st.session_state.stored_data[id]
                st.rerun()
        if st.button("Clear All Data"):
            st.session_state.clear_all = True
        if st.session_state.clear_all:
            if st.button("Confirm Clear All"):
                st.session_state.stored_data = {}
                st.session_state.clear_all = False
                st.success("🗑️ All data cleared successfully!")
                st.rerun()
    else:
        st.info("📭 No data stored yet.")

# Login Page
elif st.session_state.page == "🔑 Login":
    st.subheader("🔑 Reauthorization Required")
    st.write("Too many failed attempts detected. Please reauthorize.")
    login_pass = st.text_input("Enter Master Password:", type="password", help="Demo password: admin123")

    if st.button("Login"):
        if login_pass == "admin123":  # Hardcoded for demo
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized! Redirecting to Retrieve Data...")
            time.sleep(1)
            st.session_state.page = "🔍 Retrieve Data"
            st.rerun()
        else:
            st.error("❌ Incorrect password!")