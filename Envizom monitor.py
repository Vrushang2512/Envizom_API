"""
Envizom API Health Check with Email Alert
-------------------------------------------
Logs in to Envizom, then checks whether each API below returns HTTP 200.
Sends ONE alert email listing whatever failed (or didn't respond at all).
Designed to be run periodically via Windows Task Scheduler.

SETUP CHECKLIST (see comments marked with <-- update):
 1. pip install requests
 2. Fill in USERNAME / PASSWORD below.
 3. VERIFY (via browser DevTools, see instructions given alongside this
    file) whether the login field names and token header match what's
    guessed below - update LOGIN_PAYLOAD / AUTH_HEADER_NAME / TOKEN_JSON_PATH
    if they don't.
 4. Sign up free at https://www.brevo.com, verify a sender email, and
    grab an API key from Settings > SMTP & API > API Keys.
 5. Fill in BREVO_API_KEY, SENDER_EMAIL, RECIPIENT_EMAIL below.
 6. Schedule this script in Windows Task Scheduler.
"""

import requests
import base64
import os
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# ==================== CONFIGURATION ====================

LOGIN_URL = "https://envdevapi.oizom.com/users/login/v2"

# <-- credentials are read from environment variables (set as GitHub Actions
# secrets - see the accompanying workflow file / setup instructions). Falls
# back to placeholder text if run locally without those variables set.
USERNAME = os.environ.get("ENVIZOM_USERNAME", "YOUR_EMAIL_OR_USERNAME")
PASSWORD = os.environ.get("ENVIZOM_PASSWORD", "YOUR_PASSWORD")

# Confirmed via browser DevTools (Local Storage: ez-oz-encryption):
# the app AES-encrypts the password client-side before sending it.
ENCRYPTION_KEY = "JNyG68b3FXsxDh2PmECX6e5GRVQgFFf5"

def get_encrypted_password(password: str, key: str) -> str:
    """
    Mirrors the frontend's getEncryptedPassword(password, key):
    - key.padEnd(32, '\0') -> pad string to 32 chars with null chars
    - random 16-byte (128-bit) IV per call
    - AES-CBC + PKCS7 padding
    - output = base64(iv_bytes + ciphertext_bytes)
    """
    padded_key = key.ljust(32, '\0')
    key_bytes = padded_key.encode('utf-8')
    iv = os.urandom(16)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(password.encode('utf-8'), AES.block_size))
    return base64.b64encode(iv + ciphertext).decode('utf-8')

# Confirmed from browser DevTools: login response looks like
# {"userId": 2143, "token": {"access_token": "...", "expires_in": ...}}
TOKEN_JSON_PATH = ["token", "access_token"]

# Confirmed from browser DevTools Request Headers: the token is sent as
# "X-Access-Token: Bearer <token>" (not the standard Authorization header).
AUTH_HEADER_NAME = "X-Access-Token"
AUTH_HEADER_PREFIX = "Bearer "

# APIs to check after login (all must return HTTP 200).
# {user_id} gets filled in at runtime with YOUR account's userId (returned
# by the login response) instead of a hardcoded value - fixes "you don't
# have access to [userId=X]" errors when a different account logs in.
CHECK_URL_TEMPLATES = {
    "User Overview": (
        "https://envdevapi.oizom.com/users/{user_id}/overview/v2"
        "?userId={user_id}&profile=auto&devices_data=auto&cluster=auto&devices=auto"
        "&units=auto&aqi_and_units=auto&module_expiry=auto&org=auto&master_org=auto"
        "&device_types=auto&complain_categories=auto&latest_features=auto&modules=auto"
        "&widgets=auto&lastUpdatedToken="
    ),
    "Devices Data": (
        "https://envdevapi.oizom.com/devices/data?"
        "deviceIds=582B0A9B89BC0000&deviceIds=A81B6A6A70AA0000&deviceIds=AQ0499001"
        "&deviceIds=EADODOUR01&deviceIds=MP14672&deviceIds=MP14682&deviceIds=MP14689"
        "&deviceIds=MP14693&deviceIds=MP14694&deviceIds=MP14695&deviceIds=YG19D0003"
        "&deviceIds=YG19D0004&deviceIds=YG19D0005&deviceIds=YG19D0006&deviceIds=YG19D0007"
        "&deviceIds=YG19D0008&deviceIds=YG19D0010&deviceIds=YG19O0003"
        "&deviceIds=YG19O0004&deviceIds=YG19O0005&deviceIds=YG19P0011&deviceIds=YG19P0012"
        "&deviceIds=YG19P0013&deviceIds=YG19P0014&deviceIds=YG19P0015&deviceIds=YG19P0016"
        "&deviceIds=YG19P0017&deviceIds=YG19P0018&deviceIds=YG19P0019&deviceIds=YG19P0020"
        "&deviceIds=YG19P0021&deviceIds=YG19P0022&deviceIds=YG19P0023&deviceIds=YG19P0024"
        "&deviceIds=YG19P0025&deviceIds=YG19R0001&deviceIds=YG19R0002&deviceIds=YG19R0003"
        "&deviceIds=YG19R0004&deviceIds=YG19R0005&deviceIds=YG19R0006&deviceIds=YG19R0007"
        "&deviceIds=YG19W0001&deviceIds=CUWECP3994464&deviceIds=CUWECP3994991"
        "&deviceIds=CUWECP3994A9F&deviceIds=CUWECP3994D2D"
        "&processType=latest&userId={user_id}"
    ),
    "Last Seen / Notifications": (
        "https://envdevapi.oizom.com/users/{user_id}/last-seen"
        "?userId={user_id}&topics=header-notification"
    ),
}

REQUEST_TIMEOUT = 15  # seconds - how long to wait before treating it as "not responding"

# Some APIs behind services like Cloudflare reject or mishandle requests that
# don't look like they're coming from a browser. These mimic what the actual
# web app sends, based on your DevTools screenshots.
COMMON_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Origin": "https://devenvizom.oizom.com",
    "Referer": "https://devenvizom.oizom.com/",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-site",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
    ),
}

# ---- Email alert settings (Brevo transactional email API - no SMTP needed) ----
# <-- also read from GitHub Actions secrets, with local-run placeholders as fallback
BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "YOUR_BREVO_API_KEY")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "alerts@yourdomain.com")
RECIPIENT_EMAIL = os.environ.get("RECIPIENT_EMAIL", "you@example.com")

# =========================================================

def send_alert_email(subject, message):
    """Send an alert email using Brevo's REST API (no SMTP server needed)."""
    url = "https://api.brevo.com/v3/smtp/email"
    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json"
    }
    payload = {
        "sender": {"email": SENDER_EMAIL, "name": "Envizom Monitor"},
        "to": [{"email": RECIPIENT_EMAIL}],
        "subject": subject,
        "textContent": message
    }
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=10)
        if resp.status_code in (200, 201):
            print("Alert email sent successfully.")
        else:
            print(f"Failed to send alert email: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"Error sending alert email: {e}")

def extract_token(login_json):
    """Walk TOKEN_JSON_PATH into the login response to pull out the token."""
    value = login_json
    for key in TOKEN_JSON_PATH:
        value = value[key]
    return value

def login():
    """Attempt login. Returns (token, user_id, error_message). error_message is None on success."""
    login_payload = {
        "email": USERNAME,
        "password": get_encrypted_password(PASSWORD, ENCRYPTION_KEY)
    }
    try:
        resp = requests.post(
            LOGIN_URL, json=login_payload, headers=COMMON_HEADERS, timeout=REQUEST_TIMEOUT
        )
    except requests.exceptions.Timeout:
        return None, None, f"Login timed out after {REQUEST_TIMEOUT}s (no response at all)."
    except requests.exceptions.ConnectionError:
        return None, None, "Could not connect to Envizom login endpoint - it may be down."
    except Exception as e:
        return None, None, f"Unexpected error during login: {e}"

    if resp.status_code != 200:
        print(f"--- FULL LOGIN RESPONSE (status {resp.status_code}) ---")
        print(resp.text)
        print("--- END RESPONSE ---")
        return None, None, f"Login returned status {resp.status_code}. Response: {resp.text[:500]}"

    try:
        body = resp.json()
        token = extract_token(body)
        user_id = body.get("userId")
        if not token:
            raise ValueError("empty token")
        if not user_id:
            raise ValueError("no userId in login response")
        return token, user_id, None
    except Exception as e:
        return None, None, (
            f"Login succeeded (200) but couldn't extract token/userId using path "
            f"{TOKEN_JSON_PATH}: {e}. Raw response: {resp.text[:500]}"
        )

def check_apis(token, user_id):
    """Check each URL template (filled in with the real user_id). Returns failure strings."""
    failures = []
    headers = {**COMMON_HEADERS, AUTH_HEADER_NAME: f"{AUTH_HEADER_PREFIX}{token}"}
    for name, url_template in CHECK_URL_TEMPLATES.items():
        url = url_template.format(user_id=user_id)
        try:
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code != 200:
                failures.append(f"- {name}: HTTP {resp.status_code} - {resp.text[:200]}")
        except requests.exceptions.Timeout:
            failures.append(f"- {name}: TIMEOUT (no response within {REQUEST_TIMEOUT}s)")
        except requests.exceptions.ConnectionError:
            failures.append(f"- {name}: CONNECTION ERROR (couldn't reach it)")
        except Exception as e:
            failures.append(f"- {name}: UNEXPECTED ERROR - {e}")
    return failures

def main():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    token, user_id, login_error = login()

    if login_error:
        send_alert_email(
            "Envizom Alert: Login Failed",
            f"[{timestamp}] {login_error}"
        )
        return

    failures = check_apis(token, user_id)
    if failures:
        send_alert_email(
            "Envizom Alert: API(s) Not Responding",
            f"[{timestamp}] Login succeeded, but the following API(s) failed:\n\n"
            + "\n".join(failures)
        )
    else:
        print(f"[{timestamp}] OK - login and all {len(CHECK_URL_TEMPLATES)} API checks succeeded.")

if __name__ == "__main__":
    main()
