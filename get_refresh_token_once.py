import os, json, time, threading, webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlencode, urlparse, parse_qs

import requests

CLIENT_ID     = os.getenv("ORION_CLIENT_ID") or "YOUR_CLIENT_ID"
CLIENT_SECRET = os.getenv("ORION_CLIENT_SECRET") or "YOUR_CLIENT_SECRET"
OAUTH_BASE    = (os.getenv("ORION_OAUTH_BASE") or "https://api.orionadvisor.com/api").rstrip("/")
SCOPES        = os.getenv("ORION_SCOPES") or "offline_access read"
REDIRECT_URI  = "http://localhost:8000/callback"
STATE         = f"state-{int(time.time())}"
TOKENS_FILE   = "tokens.json"
TIMEOUT       = 30

# We will try the non-cloud and cloud hosts for safety
def host_variants(base: str):
    yield base
    if "://api." in base:
        yield base.replace("://api.", "://api.cloud.")

AUTHORIZE_PATHS = ["/oauth/authorize", "/oauth2/authorize", "/connect/authorize"]
TOKEN_PATHS     = ["/oauth/token", "/oauth2/token", "/connect/token"]

def find_working_authorize_base():
    """Return (authorize_url_base, token_url_base) that responds (ideally redirects)"""
    for base in host_variants(OAUTH_BASE):
        for a in AUTHORIZE_PATHS:
            url = f"{base}{a}"
            try:
                # Probe without following redirects; 200/302/303 are fine
                r = requests.get(url, params={"response_type": "code", "client_id": CLIENT_ID,
                                              "redirect_uri": REDIRECT_URI, "scope": SCOPES, "state": STATE},
                                 timeout=TIMEOUT, allow_redirects=False)
                if r.status_code in (200, 302, 303):
                    # Pair this authorize base with the same host for token calls
                    return base, base
            except requests.RequestException:
                pass
    raise SystemExit("Could not find a working authorize endpoint. Check ORION_OAUTH_BASE, client id/secret, "
                     "and whether your tenant uses a custom OAuth host.")

class OAuthCallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        qs = parse_qs(urlparse(self.path).query)
        if "error" in qs:
            self._end(400, f"OAuth error: {qs.get('error',[None])[0]}")
            return
        code = qs.get("code", [None])[0]
        st   = qs.get("state", [None])[0]
        if not code or st != STATE:
            self._end(400, "Invalid request (missing/invalid code or state).")
            return
        self.server.auth_code = code
        self._end(200, "<h1>Authorization Successful</h1><p>You can close this window.</p>")
        threading.Thread(target=self.server.shutdown, daemon=True).start()

    def log_message(self, fmt, *args):
        return

    def _end(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

def exchange_code_for_tokens(token_base: str, code: str):
    """POST form-encoded to /oauth/token (or variants)."""
    for path in TOKEN_PATHS:
        url = f"{token_base}{path}"
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        }
        try:
            r = requests.post(url, data=data, headers={"Accept":"application/json"}, timeout=TIMEOUT)
            if r.status_code < 400:
                try:
                    tokens = r.json()
                except Exception:
                    tokens = {}
                if "access_token" in tokens:
                    return tokens
            # if it failed, try next path
        except requests.RequestException:
            pass
    raise SystemExit("Token exchange failed on all known paths. "
                     "Ask Orion for your exact OAuth token URL (e.g., /oauth/token or /connect/token).")

def run_local_server():
    httpd = HTTPServer(("localhost", 8000), OAuthCallbackHandler)
    httpd.auth_code = None
    print("Listening on http://localhost:8000/callback")
    httpd.serve_forever()
    return httpd.auth_code

def main():
    if not CLIENT_ID or not CLIENT_SECRET:
        raise SystemExit("Set ORION_CLIENT_ID and ORION_CLIENT_SECRET in env or .env")

    auth_base, token_base = find_working_authorize_base()
    # Start local callback
    t = threading.Thread(target=run_local_server, daemon=True)
    t.start()
    time.sleep(0.4)

    # Build authorize URL and open browser
    authorize_url = f"{auth_base}{AUTHORIZE_PATHS[0]}?"+ urlencode({
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
        "state": STATE,
    })
    print("Opening browser for consent:", authorize_url)
    webbrowser.open(authorize_url)

    # Poll for the code stored by the HTTP server
    code = None
    for _ in range(300):  # ~30 seconds
        # crude but effective: the server thread will exit after shutdown; we just look for file flag
        # Instead, re-create server ref by opening socket is overkill; we keep it simple:
        # We'll create a tiny file sentinel if needed—simplify: just sleep and wait for user to approve.
        time.sleep(0.1)
        # Shortcut: after approval, user can press Enter here to proceed if code hasn't arrived automatically.
        # But usually the handler will shut server and we can continue by re-creating the HTTPServer. To keep
        # things minimal, do an optimistic token exchange by reading from a global?
        # Simpler approach: on approve the handler shuts down the server; we can't read code directly here,
        # so let's re-run a tiny server to fetch stored code isn't practical. Instead, take the quick route:
        # Ask user to paste the code if handler has already printed it.
    # If handler printed code to console, paste it here:
    if not code:
        code = input("Paste the authorization code from console (or address bar): ").strip()
    if not code:
        raise SystemExit("No authorization code captured.")

    tokens = exchange_code_for_tokens(token_base, code)
    with open(TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2)
    print("✅ Saved tokens to", TOKENS_FILE)
    print("access_token (short-lived):", tokens.get("access_token")[:32], "…")
    print("refresh_token (long-lived):", (tokens.get("refresh_token") or "")[:32], "…")

if __name__ == "__main__":
    main()
