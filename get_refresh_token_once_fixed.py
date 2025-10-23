import os, json, time, threading, webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlencode, urlparse, parse_qs

import requests

# --------- CONFIG (set these via environment or edit here) ----------
CLIENT_ID     = os.getenv("ORION_CLIENT_ID",     "2145")
CLIENT_SECRET = os.getenv("ORION_CLIENT_SECRET", "35b51998-3b61-4b3b-afff-c1269511c670")
# MUST match your Swagger's base. Examples:
#  https://api.orionadvisor.com/api
#  https://testapi.orionadvisor.com/api
#  https://stagingapi.orionadvisor.com/api
#  https://api.cloud.orionadvisor.com/api
OAUTH_BASE    = (os.getenv("ORION_OAUTH_BASE") or "https://api.orionadvisor.com/api").rstrip("/")

# Scopes: include offline_access to get a refresh_token
SCOPES        = os.getenv("ORION_SCOPES", "offline_access read")

REDIRECT_URI  = os.getenv("REDIRECT_URI", "http://localhost:8000/callback")
TOKENS_FILE   = os.getenv("TOKENS_FILE",  "tokens.json")
STATE         = f"state-{int(time.time())}"
TIMEOUT       = 30

AUTHORIZE_PATHS = ["/oauth/authorize", "/oauth2/authorize", "/connect/authorize"]
TOKEN_PATHS     = ["/oauth/token", "/oauth2/token", "/connect/token"]

# If your tenant lives on the cloud host, we’ll try that automatically:
def host_variants(base: str):
    yield base
    if "://api." in base:
        yield base.replace("://api.", "://api.cloud.")

class OAuthCallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        qs = parse_qs(urlparse(self.path).query)
        if "error" in qs:
            return self._end(400, f"OAuth error: {qs.get('error',[None])[0]}")
        code = qs.get("code", [None])[0]
        st   = qs.get("state", [None])[0]
        if not code or st != STATE:
            return self._end(400, "Invalid request (missing/invalid code or state).")
        self.server.auth_code = code
        self._end(200, "<h1>Authorization Successful</h1><p>You can close this window.</p>")
        threading.Thread(target=self.server.shutdown, daemon=True).start()

    def log_message(self, fmt, *args):  # quiet server logs
        return

    def _end(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

def find_authorize_url():
    for base in host_variants(OAUTH_BASE):
        for ap in AUTHORIZE_PATHS:
            url = f"{base}{ap}"
            try:
                r = requests.get(
                    url,
                    params={
                        "response_type": "code",
                        "client_id": CLIENT_ID,
                        "redirect_uri": REDIRECT_URI,
                        "scope": SCOPES,
                        "state": STATE,
                    },
                    timeout=TIMEOUT,
                    allow_redirects=False,
                )
                if r.status_code in (200, 302, 303, 401):  # 401 is fine (login screen)
                    return base, url
            except requests.RequestException:
                pass
    raise SystemExit("No working AUTHORIZE endpoint. Set ORION_OAUTH_BASE to your Swagger base (e.g. https://stagingapi.orionadvisor.com/api).")

def exchange_code_for_tokens(token_base: str, code: str):
    for tp in TOKEN_PATHS:
        url = f"{token_base}{tp}"
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        }
        try:
            r = requests.post(url, data=data, headers={"Accept": "application/json"}, timeout=TIMEOUT)
            if r.status_code < 400:
                try:
                    tokens = r.json()
                except Exception:
                    tokens = {}
                if tokens.get("access_token"):
                    return tokens
        except requests.RequestException:
            pass
    raise SystemExit("Token exchange failed on all known paths. Ask Orion for your exact OAuth token URL (/oauth/token or /connect/token).")

def run_local_server_get_code():
    httpd = HTTPServer(("localhost", 8000), OAuthCallbackHandler)
    httpd.auth_code = None
    print("Listening on http://localhost:8000/callback")
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    # wait up to 3 minutes for the handler to set auth_code then shutdown
    for _ in range(1800):
        if t.is_alive():
            time.sleep(0.1)
        else:
            break
    return getattr(httpd, "auth_code", None)

def main():
    if not CLIENT_ID or not CLIENT_SECRET:
        raise SystemExit("Set ORION_CLIENT_ID and ORION_CLIENT_SECRET (env or .env)")

    base, authorize_url = find_authorize_url()
    # pick a token base on same host as authorize
    token_base = base

    # start local server
    srv = threading.Thread(target=run_local_server_get_code, daemon=True)
    srv.start()
    time.sleep(0.5)

    # open browser for consent
    url = f"{authorize_url.split('?')[0]}?"+ urlencode({
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
        "state": STATE,
    })
    print("Opening browser:", url)
    webbrowser.open(url)

    # prompt as fallback if code wasn’t captured
    code = input("If the page didn’t close itself, paste the 'code' from the address bar here (or just press Enter to skip): ").strip()
    if not code:
        # try one more time to read from server thread by running a quick server once more
        print("Waiting briefly for callback...")
        time.sleep(3)

    # Best-effort: ask once more
    if not code:
        code = input("Paste authorization code (if available): ").strip()
    if not code:
        raise SystemExit("No authorization code captured. Make sure REDIRECT_URI is whitelisted and matches exactly.")

    tokens = exchange_code_for_tokens(token_base, code)
    with open(TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2)
    print("✅ Saved tokens to", TOKENS_FILE)
    print("access_token (short):", tokens.get("access_token", "")[:40], "…")
    print("refresh_token (long):", tokens.get("refresh_token", "")[:40], "…")

if __name__ == "__main__":
    main()
