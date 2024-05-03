import hashlib
import requests
import bs4
import concurrent.futures
import pandas as pd
import streamlit as st
import base64
import re
import urllib.parse
import threading

SECRET = ""
SESSION = requests.Session()
TIMER = None

MAILBOX_LAYER_URL = "https://mailboxlayer.com/"
API_BASE_URL = "https://mailboxlayer.com/php_helper_scripts/email_api_n.php"

def get_secret():
    global SECRET
    response = SESSION.get(MAILBOX_LAYER_URL)
    soup = bs4.BeautifulSoup(response.text, "html.parser")
    secret = soup.select_one("input[name='scl_request_secret']").get("value")
    if secret != SECRET:
        print("New secret obtained!")
        SECRET = secret
        print(SECRET)
    return secret

def is_valid_email(email):
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email.strip())

def generate_hash(email_address, secret):
    message = email_address + secret
    return hashlib.md5(message.encode("utf-8")).hexdigest()

def get_status(email, _hash=None):
    global SECRET
    if not is_valid_email(email):
        return None
    if not _hash:
        _hash = generate_hash(email, SECRET)
    url = f"{API_BASE_URL}?secret_key={_hash}&email_address={urllib.parse.quote(email)}"
    payload = {}
    headers = {}
    try:
        requests.get("https://kounter.tk/badge/email_all")
    except:
        pass
    response = SESSION.request("GET", url, headers=headers, data=payload)
    if response.text == "Unauthorized":
        print(email, "------", url, "------", response.text)
        return process_email(email)
    else:
        response = response.json()
        try:
            if response["score"] > 0.5:
                print(response)
                try:
                    requests.get("https://kounter.tk/badge/email_valid")
                except:
                    pass
                return response
            else:
                return None
        except:
            return None

def update_secret():
    get_secret()
    global TIMER
    TIMER = threading.Timer(5, update_secret)
    TIMER.start()

def stop_timer():
    global TIMER
    if TIMER:
        TIMER.cancel()

def process_email(email):
    global SECRET
    get_secret()
    _hash = generate_hash(email, SECRET)
    return get_status(email, _hash)

def validate_emails(emails, progress_bar):
    valid_emails = []
    update_secret()  # start the timer

    with concurrent.futures.ThreadPoolExecutor(max_workers=9) as executor:
        futures = [executor.submit(process_email, email) for email in emails]

        spinner_text = "Validating email addresses..."
        with st.spinner(spinner_text):
            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                email = future.result()
                if email:
                    valid_emails.append(email)
                progress = (i + 1) / len(emails)
                progress_bar.progress(progress)

    stop_timer()
    return valid_emails

def main():
    st.set_page_config(page_title="Email Validator", page_icon=":envelope:")
    st.title("Email Address Validator")
    
    st.markdown("""
        This app allows you to validate email addresses from a CSV file or text input.
        
        **To validate email addresses from a CSV file:**
        1. Click on the "Upload CSV file" section in the sidebar.
        2. Select a CSV file containing email addresses.
        3. Choose the column containing the email addresses.
        4. Click the "Validate Email" button to start validation.
        
        **To validate email addresses from text input:**
        1. Enter a list of email addresses separated by commas in the field below.
        2. Click the "Validate Email" button to start validation.
        
        The validated email addresses will be displayed in a table below. You can select which columns to display using the dropdown menu. You can also download the validated email addresses as a CSV file by clicking the "Download CSV" button.
    """)
    
    if "valid_emails" not in st.session_state:
        st.session_state.valid_emails = []

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
            st.session_state.valid_emails += validate_emails(df[column_name].tolist(), progress_bar)

    # Validate email addresses from text input
    st.sidebar.write("### Enter email addresses")
    email_input = st.sidebar.text_input("Enter email addresses (separated by comma)")
    if email_input:
        emails = [email.strip() for email in email_input.split(",")]

        if st.sidebar.button("Validate Email", key="validate_text_button"):
            total_emails = len(emails)
            st.info(f"Total emails to process: {total_emails}")
            
            progress_bar = st.progress(0)
            st.session_state.valid_emails += validate_emails(emails, progress_bar)

    # Display the validated email addresses
    if st.session_state.valid_emails:
        st.write(f"Found {len(st.session_state.valid_emails)} valid email addresses.")

        columns = st.session_state.valid_emails[0].keys()
        visible_columns = st.multiselect("Select columns to show", list(columns), default=list(columns))
        
        valid_email_df = pd.DataFrame(st.session_state.valid_emails)[visible_columns]
        st.write(valid_email_df)
        
        csv = valid_email_df.to_csv(index=False)
        b64 = base64.b64encode(csv.encode()).decode()
        button_label = "Download CSV"
        button_download = f'<a href="data:file/csv;base64,{b64}" download="valid_emails.csv">{button_label}</a>'
        st.markdown(button_download, unsafe_allow_html=True)

    # Move the "Clear" button to the top of the sidebar
    st.sidebar.markdown("---")
    if st.sidebar.button("Clear", key="clear_button"):
        st.sidebar.empty()
        st.session_state.valid_emails = []

if __name__ == "__main__":
    main()
