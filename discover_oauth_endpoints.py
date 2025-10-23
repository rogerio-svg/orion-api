import os, sys, time
from urllib.parse import urlencode
import requests

CLIENT_ID     = os.getenv("ORION_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("ORION_CLIENT_SECRET", "")
REDIRECT_URI  = os.getenv("REDIRECT_URI", "http://localhost:8000/callback")
STATE = f"state-{int(time.time())}"
TIMEOUT = 12

if not CLIENT_ID or not CLIENT_SECRET:
    sys.exit("Set ORION_CLIENT_ID and ORION_CLIENT_SECRET in env first.")

# Hosts to try (prod). If you're on test/staging, add those too.
HOSTS = [
    "https://api.orionadvisor.com",
    "https://api.orionadvisor.com/api",
    "https://api.cloud.orionadvisor.com",
    "https://api.cloud.orionadvisor.com/api",
    "https://login.orionadvisor.com",
    "https://login.cloud.orionadvisor.com",
    "https://identity.orionadvisor.com",
    "https://identity.cloud.orionadvisor.com",
]

AUTHORIZE_PATHS = ["/oauth/authorize", "/oauth2/authorize", "/connect/authorize", "/authorize"]
TOKEN_PATHS     = ["/oauth/token", "/oauth2/token", "/connect/token", "/token"]

def probe_authorize():
    print("== Probing AUTHORIZE endpoints ==")
    found = []
    for base in HOSTS:
        for path in AUTHORIZE_PATHS:
            url = f"{base}{path}"
            try:
                r = requests.get(
                    url,
                    params={
                        "response_type": "code",
                        "client_id": CLIENT_ID,
                        "redirect_uri": REDIRECT_URI,
                        "scope": "offline_access read",
                        "state": STATE,
                    },
                    timeout=TIMEOUT,
                    allow_redirects=False,
                )
                if r.status_code in (200, 302, 303, 401):  # 401 is OK (auth page)
                    found.append(url)
                    print(f"  OK  {r.status_code}  {url}")
            except requests.RequestException as e:
                pass
    return found

def probe_token(base_candidates):
    print("\n== Probing TOKEN endpoints on matching hosts ==")
    found = []
    for auth_url in base_candidates:
        # use same host portion for token
        if "/oauth" in auth_url:
            token_base = auth_url.split("/oauth")[0]
        elif "/connect" in auth_url:
            token_base = auth_url.split("/connect")[0]
        else:
            token_base = auth_url.rsplit("/", 1)[0]
        for path in TOKEN_PATHS:
            url = f"{token_base}{path}"
            try:
                r = requests.post(
                    url,
                    data={
                        "grant_type": "client_credentials",  # just to see if endpoint exists
                        "client_id": CLIENT_ID,
                        "client_secret": CLIENT_SECRET,
                    },
                    headers={"Accept": "application/json"},
                    timeout=TIMEOUT,
                )
                if r.status_code in (200, 400, 401):  # 400/401 still proves endpoint exists
                    print(f"  OK  {r.status_code}  {url}")
                    found.append(url)
            except requests.RequestException:
                pass
    return found

if __name__ == "__main__":
    auth_candidates = probe_authorize()
    if not auth_candidates:
        sys.exit("\nNo working AUTHORIZE endpoint found. If you’re on TEST/STAGING, add those hosts to HOSTS and re-run.")
    token_candidates = probe_token(auth_candidates)
    if not token_candidates:
        print("\nAuthorize endpoint(s) found, but token endpoint not obvious.\n"
              "Tell me which AUTHORIZE URL worked and I’ll map the TOKEN URL exactly.")
    else:
        print("\n== Summary ==")
        print("Working AUTHORIZE candidates:")
        for u in auth_candidates: print(" -", u)
        print("Working TOKEN candidates:")
        for u in token_candidates: print(" -", u)
