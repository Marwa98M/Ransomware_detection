import streamlit as st
import pandas as pd
import numpy as np
import hashlib
import requests
import tensorflow as tf
from sklearn.metrics import accuracy_score
import time

# ------------------------- CONFIG -------------------------
VIRUSTOTAL_API_KEY = "8fba002a70060f8ed27e4a059d49a1faa91de2a1ea35344f6b42158f1967d0ee"

# ------------------------- VIRUSTOTAL -------------------------
def upload_and_check_file_virustotal(file_obj, filename):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    files = {"file": (filename, file_obj)}
    response = requests.post(url, headers=headers, files=files)
    if response.status_code not in (200, 202):
        return "Unknown"
    analysis_id = response.json().get("data", {}).get("id")
    time.sleep(10)
    result = get_analysis_result(analysis_id)
    return result

def get_analysis_result(analysis_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    for _ in range(10):
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            status = response.json().get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                stats = response.json().get("data", {}).get("attributes", {}).get("stats", {})
                return "Ransomware" if stats.get("malicious", 0) > 0 else "Benign"
        time.sleep(3)
    return "Unknown"

# ------------------------- RULE BASED -------------------------
def detect_ransomware(df):
    # Map numeric columns to expected features
    df['throughput_diff'] = df.iloc[:, 1] - df.iloc[:, 0]  # throughput_write - throughput_read
    
    return (
        (df.iloc[:, 2] > 0.12) & (df.iloc[:, 3] > 0.043) & (df.iloc[:, 0] > 2.2e6) |
        (df.iloc[:, 4] > 3.6) & (df.iloc[:, 2] > 0.08) & (df.iloc[:, 3] > 0.032) |
        (df.iloc[:, 1] > 6.0e6) & (df.iloc[:, 5] > 2.8) & (df.iloc[:, 6] < 0.9) |
        (df.iloc[:, 7] > 2.3e14) & (df.iloc[:, 2] > 0.07) |
        (df.iloc[:, 8] > 4.0) & (df.iloc[:, 2] > 0.04) & (df.iloc[:, 9] > 0.91) |
        (df['throughput_diff'] > -3.5e6)
    ).astype(int)

# ------------------------- AI BASED -------------------------
def load_dl_model():
    try:
        model = tf.keras.models.load_model('model.h5')
        return model
    except Exception as e:
        st.error(f"Error loading the model: {e}")
        return None

def ai_model_predict(model, df):
    preds = model.predict(df)
    binary_preds = (preds > 0.5).astype(int).flatten()
    return binary_preds

# ------------------------- MAIN FUNCTION -------------------------
def main():
    st.title("RansRadar - Smart Ransomware Detector")
    st.write("Upload a file for automatic analysis via VirusTotal, Rule-Based Detection, and Deep Learning.")

    uploaded_file = st.file_uploader("Upload any file (CSV or binary)", type=None)

    if uploaded_file:
        result_flags = []

        if uploaded_file.name.endswith(".csv"):
            df = pd.read_csv(uploaded_file)

            # Rule-based check
            try:
                rule_preds = detect_ransomware(df)
                if rule_preds.sum() > 0:
                    result_flags.append("Ransomware")
                else:
                    result_flags.append("Benign")
            except Exception as e:
                st.error(f"Rule-based error: {e}")

            # Deep Learning check (operates on full DataFrame)
            try:
                model = load_dl_model()
                if model:
                    # with st.spinner('Running deep learning analysis...'):
                        # Get predictions for all records (0-1 values)
                        predictions = (model.predict(df.values) > 0.5).astype(int)
                        
                        # Calculate ransomware ratio
                        ransomware_count = np.sum(predictions)
                        total_rows = len(predictions)
                        ransomware_ratio = ransomware_count / total_rows
                        # st.write(f"- Ransomware rows: {ransomware_count}")
                        # st.write(f"- Ransomware ratio: {ransomware_ratio}")
                        
                        # Determine file classification
                        file_verdict = "Ransomware" if ransomware_ratio > 0.5 else "Benign"
                        result_flags.append(file_verdict)

            except Exception as e:
                st.error(f"Deep Learning Error: {str(e)}")
                    

        else:
            # Non-CSV → VirusTotal scan
            vt_result = upload_and_check_file_virustotal(uploaded_file, uploaded_file.name)
            result_flags.append(vt_result)

        # Final decision
               # Final decision
        st.subheader("🧾 Detection Summary")
        st.write("Results from each model:")

        model_sources = []

        if uploaded_file.name.endswith(".csv"):
            model_sources.append("✔️ Rule-Based Model: " + ("Ransomware" if "Ransomware" in result_flags[:1] else "Benign"))
            if len(result_flags) > 1:
                model_sources.append("🤖 Deep Learning Model: " + ("Ransomware" if "Ransomware" in result_flags[1:2] else "Benign"))
        else:
            model_sources.append("🛡️ VirusTotal Scan: " + result_flags[0])

        for line in model_sources:
            st.write(line)

        st.markdown("---")

        # Verdict
        if "Ransomware" in result_flags:
            st.error("🔴 **Final Verdict: Ransomware Detected**")
        elif all(flag == "Benign" for flag in result_flags):
            st.success("🟢 **Final Verdict: Benign File**")
        else:
            st.warning("⚠️ **Final Verdict: Inconclusive**")


if __name__ == '__main__':
    main()