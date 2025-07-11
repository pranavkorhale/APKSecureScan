import streamlit as st
import requests
import json
import os
import time
import subprocess
from requests_toolbelt.multipart.encoder import MultipartEncoder
from dotenv import load_dotenv

# === Load .env ===
load_dotenv()

# === Configuration ===
API_KEY = os.getenv("API_KEY")
MOBSF_URL = os.getenv("MOBSF_URL")
MAX_RETRIES = 10
RETRY_DELAY = 20
REPORT_PATH = "./output_files/mobsf_report.json"

# === API Functions ===
def make_api_request(method, endpoint, data=None, files=None, json_data=None):
    headers = {
        "Authorization": API_KEY,
        "Content-Type": "application/json" if json_data else "application/x-www-form-urlencoded"
    }
    url = f"{MOBSF_URL}{endpoint}"
    response = requests.request(method, url, headers=headers, data=data, files=files, json=json_data, timeout=300)
    response.raise_for_status()
    return response.json()

def upload_file_to_mobsf(uploaded_file):
    multipart_data = MultipartEncoder(
        fields={'file': (uploaded_file.name, uploaded_file, 'application/vnd.android.package-archive')}
    )
    headers = {
        "Authorization": API_KEY,
        "Content-Type": multipart_data.content_type
    }
    response = requests.post(f"{MOBSF_URL}/api/v1/upload", data=multipart_data, headers=headers, timeout=300)
    response.raise_for_status()
    return response.json()

def start_scan(upload_data):
    return make_api_request("POST", "/api/v1/scan", data={
        "hash": upload_data['hash'],
        "scan_type": upload_data['scan_type'],
        "file_name": upload_data['file_name'],
        "re_scan": "0"
    })

def generate_json_report(hash_value):
    for attempt in range(MAX_RETRIES):
        try:
            try:
                report = make_api_request("POST", "/api/v1/report_json", json_data={"hash": hash_value})
            except:
                report = make_api_request("POST", "/api/v1/report_json", data={"hash": hash_value})
            if 'error' in report:
                raise Exception(report['error'])
            return report
        except Exception as e:
            if attempt == MAX_RETRIES - 1:
                raise Exception(f"Failed after {MAX_RETRIES} attempts: {str(e)}")
            time.sleep(RETRY_DELAY)

# === Streamlit UI ===
st.set_page_config(
    page_title="APK Analyzer", 
    layout="wide",  # Changed from "centered" to "wide"
    initial_sidebar_state="expanded"
)

# Custom CSS to maximize space utilization
st.markdown("""
    <style>
        .main .block-container {
            padding-top: 2rem;
            padding-bottom: 2rem;
            padding-left: 3rem;
            padding-right: 3rem;
        }
        .stFileUploader {
            width: 100% !important;
        }
        .stFileUploader > div {
            width: 100% !important;
        }
    </style>
""", unsafe_allow_html=True)

st.title("📱 APK Malware Analyzer")

# Make file uploader wider
uploaded_apk = st.file_uploader(
    "Upload your APK file", 
    type=["apk"],
    label_visibility="visible"
)

if uploaded_apk:
    try:
        with st.spinner("🔄 Processing APK..."):
            upload_response = upload_file_to_mobsf(uploaded_apk)
            start_scan(upload_response)
            report = generate_json_report(upload_response["hash"])

            with open(REPORT_PATH, 'w') as f:
                json.dump(report, f, indent=2)

        st.success("✅ Static Analysis Complete")

        # === Post-processing with LLM scripts ===
        st.subheader("📋 Threat Intelligence Summary")
        
        # Create two columns with adjusted width ratios
        col1, col2 = st.columns([1, 1])  # Equal width columns
        
        with st.spinner("Analyzing Permissions..."):
            result1 = subprocess.run(
                ["python3", "Permission Extracter/permission_to_LLM.py"],
                capture_output=True, text=True
            )
            permission_summary = result1.stdout.strip().split("📋 Executive Summary:")[-1].strip()
            
        with st.spinner("Analyzing Sensitive APIs..."):
            result2 = subprocess.run(
                ["python3", "sesitive APIs/sensitiveAPI_to_LLM.py"],
                capture_output=True, text=True
            )
            api_summary = result2.stdout.strip().split("📋 Executive Summary:")[-1].strip()
        
        # Display results in columns with borders and increased height
        with col1:
            st.markdown(
                f"""
                <div style="
                    padding: 15px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    height: 400px;
                    overflow-y: auto;
                    background-color: #f9f9f9;
                ">
                <h3 style='color: #2e86c1;'>Permission Analysis</h3>
                <hr style='margin: 10px 0;'>
                {permission_summary}
                </div>
                """,
                unsafe_allow_html=True
            )
        
        with col2:
            st.markdown(
                f"""
                <div style="
                    padding: 15px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    height: 400px;
                    overflow-y: auto;
                    background-color: #f9f9f9;
                ">
                <h3 style='color: #2e86c1;'>Sensitive API Analysis</h3>
                <hr style='margin: 10px 0;'>
                {api_summary}
                </div>
                """,
                unsafe_allow_html=True
            )

        st.success("✅ Final Executive Summaries Generated!")

    except Exception as e:
        st.error(f"❌ Error: {str(e)}")