from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import joblib  # for loading the trained model
from urllib.parse import urlparse
import re
import csv
import tldextract



app = Flask(__name__)
CORS(app)

# ------------------ Load trained model ------------------
model = joblib.load("rf_model.pkl")  # Replace with your model path

# ------------------ Feature extraction ------------------

def extract_url_features_from_string(url):
    df = pd.DataFrame([{'url': url}])

    def having_ip_address(url):
        match = re.search(
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}'
            r'([01]?\d\d?|2[0-4]\d|25[0-5])|'
            r'((0x[0-9a-fA-F]{1,2})\.){3}'
            r'(0x[0-9a-fA-F]{1,2})|'
            r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)
        return 1 if match else 0

    def is_hostname_correct(url):
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            if hostname is None:
                return 1
            match = re.search(r'https?:\/\/[^\/]*' + re.escape(str(hostname)), url)
            return 0 if match else 1
        except:
            return 1

    def count_special_chars(url):
        special_chars = "!@#$%^&*()_+=}{[]|\\;:'\"<>,?"
        return sum(1 for char in url if char in special_chars)

    def shortening_service(url):
        return 1 if re.search(r'bit\.ly|goo\.gl|tinyurl\.com|t\.co|is\.gd|buff\.ly|adf\.ly|bit\.do', url) else 0

    def digit_count(url): return sum(c.isdigit() for c in url)
    def hostname_length(url): return len(urlparse(url).netloc)
    def count_www(url): return url.count("www")
    def count_http(url): return url.count("http")
    def count_https(url): return url.count("https")
    def count_double_slash(url): return url.count("//")
    def if_http_and_https_both_present(url):
        return 1 if "https" in url and "http" in url.replace("https", "") else 0

    df['use_of_ip'] = df['url'].apply(having_ip_address)
    df['abnormal_url'] = df['url'].apply(is_hostname_correct)
    df['url_length'] = df['url'].apply(len)
    df['special_chars_count'] = df['url'].apply(count_special_chars)
    df['dot_count'] = df['url'].apply(lambda x: x.count('.'))
    df['http_count'] = df['url'].apply(count_http)
    df['https_count'] = df['url'].apply(count_https)
    df['http_https_both'] = df['url'].apply(if_http_and_https_both_present)
    df['shortening_service'] = df['url'].apply(shortening_service)
    df['digit_count'] = df['url'].apply(digit_count)
    df['www_count'] = df['url'].apply(count_www)
    df['at_count'] = df['url'].apply(lambda x: x.count('@'))
    df['double_slash_count'] = df['url'].apply(count_double_slash)
    df['hostname_length'] = df['url'].apply(hostname_length)

    return df.drop(columns=['url'])

# ------------------ API Route ------------------



import requests
import time

def check_url_virustotal(url, api_key= "743d733013b6ecea5219429929573a11c7d598d79ddd6a9796f2223be704ce0f", max_retries=5, wait_seconds=5):
    headers = {
        "x-apikey": api_key,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    def submit_url():
        scan_url = "https://www.virustotal.com/api/v3/urls"
        response = requests.post(scan_url, headers=headers, data=f"url={url}")
        if response.status_code != 200:
            raise Exception(f"Error submitting URL: {response.text}")
        return response.json()["data"]["id"]

    def fetch_analysis(scan_id):
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        return requests.get(analysis_url, headers=headers)

    for attempt in range(max_retries):
        try:
            scan_id = submit_url()
            time.sleep(wait_seconds)
            response = fetch_analysis(scan_id)

            if response.status_code != 200:
                print(f"Error retrieving results (attempt {attempt + 1}):", response.text)
                continue

            stats = response.json()["data"]["attributes"]["stats"]

            harmless = stats.get("harmless", 0)
            suspicious = stats.get("suspicious", 0)
            malicious = stats.get("malicious", 0)
            undetected = stats.get("undetected", 0)

            total = harmless + suspicious + malicious + undetected

            # If all counts are zero, wait and retry
            if total == 0:
                print(f"Attempt {attempt + 1}: No results yet. Retrying...")
                time.sleep(wait_seconds)
                continue

            print("Scan Results:")
            print(f"✅ Harmless: {harmless}")
            print(f"⚠️ Suspicious: {suspicious}")
            print(f"❌ Malicious: {malicious}")
            print(f"🛑 Undetected: {undetected}")

            if malicious > 0 or suspicious > 0:
                print("🚫 This URL is potentially dangerous.")
                return False
            else:
                print("✅ This URL appears safe.")
                return True

        except Exception as e:
            print(f"Error during attempt {attempt + 1}:", e)

    print("❗ Unable to get reliable scan results after several attempts.")
    return None

# Example usage


def check_url_trust(url, trusted_domains_file='trusteddomain.csv'):
    
    trusted = set()
    try:
        with open(trusted_domains_file, 'r', newline='', encoding='utf-8') as file:
            reader = csv.reader(file)
            for row in reader:
                if len(row) >= 2:
                    domain = row[1].strip().lower()
                    if domain:
                        trusted.add(domain)
    except FileNotFoundError:
        print(f"Trusted domains file not found: {trusted_domains_file}")
        return 0  

    try:
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}".lower()
        return 0 if domain in trusted else 1
    except Exception as e:
        print(f"Error processing URL '{url}': {e}")
        return 0
    
    










@app.route('/check', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    try:
        features_df = extract_url_features_from_string(url)
        model_prediction = model.predict(features_df)[0]
        vstool_prediction = check_url_virustotal(url)
        last_prediction = 1
        if model_prediction== 0 :
            if vstool_prediction :
                last_prediction = 0 
            else :
                last_prediction = check_url_trust(url)
        else :
            if vstool_prediction :
                last_prediction= check_url_trust(url)
            else :
               last_prediction = 1 
        return jsonify({'malicious': int(last_prediction)})
    except Exception as e:
        return jsonify({'error': f'Error during prediction: {str(e)}'}), 500

# ------------------ Run Server ------------------

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
