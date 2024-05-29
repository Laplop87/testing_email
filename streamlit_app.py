import hashlib
import requests
import bs4
import concurrent.futures
import pandas as pd
import streamlit as st
import re
import urllib.parse
import threading
import base64
import time

SECRET = ""
SESSION = requests.Session()
TIMER = None

MAILBOX_LAYER_URL = "https://mailboxlayer.com/"
API_BASE_URL = "https://mailboxlayer.com/php_helper_scripts/email_api_n.php"

def get_secret():
    global SECRET
    while not SECRET:  # Retry until a valid secret is obtained
        try:
            response = SESSION.get(MAILBOX_LAYER_URL)
            soup = bs4.BeautifulSoup(response.text, "html.parser")
            secret_input = soup.select_one("input[name='scl_request_secret']")
            if secret_input:
                SECRET = secret_input.get("value")
                print("New secret obtained:", SECRET)
            else:
                print("Secret not found. Retrying...")
                time.sleep(5)  # Wait before retrying
        except requests.RequestException as e:
            print(f"Error fetching secret: {e}")
            time.sleep(5)  # Wait before retrying

def is_valid_email(email):
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email.strip())

def generate_hash(email_address, secret):
    message = email_address + secret
    return hashlib.md5(message.encode("utf-8")).hexdigest()

def get_status(email, _hash=None):
    global SECRET
    if not is_valid_email(email):
        return {"email": email, "status": "invalid"}
    if not SECRET:
        get_secret()  # Ensure we have a valid secret
    _hash = generate_hash(email, SECRET)
    url = f"{API_BASE_URL}?secret_key={_hash}&email_address={urllib.parse.quote(email)}"
    response = SESSION.get(url)
    if response.text == "Unauthorized":
        return process_email(email)
    else:
        try:
            response = response.json()
            if response.get("score", 0) > 0.5:
                return {"email": email, "status": "valid"}
            else:
                return {"email": email, "status": "invalid"}
        except ValueError:
            print(f"Error decoding JSON response for {email}")
            return {"email": email, "status": "unknown"}

def update_secret():
    global TIMER
    get_secret()
    TIMER = threading.Timer(60, update_secret)  # Schedule update after 60 seconds
    TIMER.start()

def stop_timer():
    global TIMER
    if TIMER:
        TIMER.cancel()

def process_email(email):
    global SECRET
    get_secret()  # Ensure we have a valid secret
    _hash = generate_hash(email, SECRET)
    return get_status(email, _hash)

def validate_emails(emails, progress_bar):
    email_statuses = []
    update_secret()  # Start the secret update timer

    with concurrent.futures.ThreadPoolExecutor(max_workers=9) as executor:
        futures = [executor.submit(process_email, email) for email in emails]

        spinner_text = "Validating email addresses..."
        with st.spinner(spinner_text):
            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                email_status = future.result()
                email_statuses.append(email_status)
                progress = (i + 1) / len(emails)
                progress_bar.progress(progress)

    stop_timer()  # Stop the secret update timer
    return email_statuses

def main():
    st.set_page_config(page_title="Email Validator", page_icon=":envelope:")
    st.title("Email Address Validator")

    st.markdown("""
        This app allows you to validate email addresses from a CSV file.
        
        **To validate email addresses from a CSV file:**
        1. Click on the "Upload CSV file" section in the sidebar.
        2. Select a CSV file containing email addresses.
        3. Choose the column containing the email addresses.
        4. Click the "Validate Email" button to start validation.
    """)

    if "email_statuses" not in st.session_state:
        st.session_state.email_statuses = []

    # Validate email addresses from uploaded CSV file
    st.sidebar.write("### Upload CSV file")
    uploaded_file = st.sidebar.file_uploader("Choose a CSV file", type="csv")
    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        column_name = st.sidebar.selectbox("Select email column", df.columns)

        if st.sidebar.button("Validate Email", key="validate_csv_button"):
            total_emails = len(df)
            st.info(f"Total emails to process: {total_emails}")
            
            progress_bar = st.progress(0)
            st.session_state.email_statuses += validate_emails(df[column_name].tolist(), progress_bar)

    # Display the validated email addresses
    if st.session_state.email_statuses:
        st.write(f"Processed {len(st.session_state.email_statuses)} email addresses.")

        email_status_df = pd.DataFrame(st.session_state.email_statuses)
        st.write(email_status_df)
        
        csv = email_status_df.to_csv(index=False)
        b64 = base64.b64encode(csv.encode()).decode()
        button_label = "Download CSV"
        button_download = f'<a href="data:file/csv;base64,{b64}" download="email_statuses.csv">{button_label}</a>'
        st.markdown(button_download, unsafe_allow_html=True)

    # Clear the validated emails
    st.sidebar.markdown("---")
    if st.sidebar.button("Clear", key="clear_button"):
        st.sidebar.empty()
        st.session_state.email_statuses = []

if __name__ == "__main__":
    main()
