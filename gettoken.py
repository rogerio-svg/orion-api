import os
import sys
import base64
import json
import requests

# ---- CONFIG ----
# Switch to PRODUCTION by setting BASE to "https://api.orionadvisor.com/api/v1"
BASE = os.getenv("ORION_BASE", "https://testapi.orionadvisor.com/api/v1")
USERNAME = os.getenv("ORION_USERNAME", "sma@astoncapital.net")
PASSWORD = os.getenv("ORION_PASSWORD", "*Aston01")

TOKEN_ENDPOINT = f"{BASE}/Security/Token"

def extract_token(payload):
    """
    Try common property names returned by various Orion tenants.
    """
    if isinstance(payload, dict):
        for key in ("access_token", "token", "Token", "value", "bearerToken", "BearerToken"):
            if key in payload and payload[key]:
                return payload[key]
    # sometimes API returns the token as raw text
    if isinstance(payload, str) and payload.strip():
        return payload.strip()
    return None

def try_get_basic():
    print("[1/3] GET /Security/Token with HTTP Basic …")
    userpass = f"{USERNAME}:{PASSWORD}".encode("utf-8")
    headers = {
        "Authorization": f"Basic {base64.b64encode(userpass).decode('utf-8')}",
        "Accept": "application/json"
    }
    r = requests.get(TOKEN_ENDPOINT, headers=headers, timeout=30)
    ctype = r.headers.get("content-type", "")
    if r.status_code >= 400:
        print(f"  -> {r.status_code} {r.reason}")
        print(f"  Response: {r.text[:500]}")
        return None
    payload = r.json() if ctype.startswith("application/json") else r.text
    token = extract_token(payload)
    if token:
        print("  ✔ token acquired (GET Basic)")
    return token

def try_post_json():
    print("[2/3] POST /Security/Token with JSON body …")
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    body = {"Username": USERNAME, "Password": PASSWORD}
    r = requests.post(TOKEN_ENDPOINT, headers=headers, json=body, timeout=30)
    ctype = r.headers.get("content-type", "")
    if r.status_code >= 400:
        print(f"  -> {r.status_code} {r.reason}")
        print(f"  Response: {r.text[:500]}")
        return None
    payload = r.json() if ctype.startswith("application/json") else r.text
    token = extract_token(payload)
    if token:
        print("  ✔ token acquired (POST JSON)")
    return token

def try_post_form():
    print("[3/3] POST /Security/Token with form-encoded body …")
    headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
    data = {"Username": USERNAME, "Password": PASSWORD}
    r = requests.post(TOKEN_ENDPOINT, headers=headers, data=data, timeout=30)
    ctype = r.headers.get("content-type", "")
    if r.status_code >= 400:
        print(f"  -> {r.status_code} {r.reason}")
        print(f"  Response: {r.text[:500]}")
        return None
    payload = r.json() if ctype.startswith("application/json") else r.text
    token = extract_token(payload)
    if token:
        print("  ✔ token acquired (POST form)")
    return token

if __name__ == "__main__":
    # Allow quick override from command line:
    #   python gettoken.py test|prod username password
    if len(sys.argv) >= 2:
        env = sys.argv[1].lower()
        if env == "prod":
            BASE = "https://api.orionadvisor.com/api/v1"
        else:
            BASE = "https://testapi.orionadvisor.com/api/v1"
    if len(sys.argv) >= 3:
        USERNAME = sys.argv[2]
    if len(sys.argv) >= 4:
        PASSWORD = sys.argv[3]

    print(f"Using BASE: {BASE}")
    print(f"User: {USERNAME}")

    token = try_get_basic() or try_post_json() or try_post_form()
    if not token:
        print("\n❌ Could not retrieve a token with the standard flows.")
        print("Things to check:")
        print("  • Are the username/password correct for API access (not just UI)?")
        print("  • Are you hitting the right environment (test vs prod)?")
        print("  • Does your tenant require 2FA before token issuance?")
        print("  • Does your firm use OAuth/Refresh Token instead of basic creds?")
        sys.exit(1)

    print("\n==== YOUR BEARER TOKEN ====\n")
    print(token)
