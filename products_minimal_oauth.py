import os, sys, csv, json, time, string, threading, webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlencode, urlparse, parse_qs
from typing import Dict, Any, List

import requests
from dotenv import load_dotenv

load_dotenv()

BASE              = os.getenv("ORION_BASE", "https://api.orionadvisor.com/api").rstrip("/")
CLIENT_ID         = os.getenv("ORION_CLIENT_ID", "")
CLIENT_SECRET     = os.getenv("ORION_CLIENT_SECRET", "")
AUTHORIZE_URL     = os.getenv("ORION_AUTHORIZE_URL", f"{BASE}/oauth/authorize")
TOKEN_URL         = os.getenv("ORION_TOKEN_URL",      f"{BASE}/oauth/token")
REDIRECT_URI      = os.getenv("REDIRECT_URI",         "http://localhost:8000/callback")
SCOPES            = os.getenv("OAUTH_SCOPES",         "read offline_access")
OUTFILE           = os.getenv("OUTPUT_FILE",          "products.csv")
TIMEOUT           = int(os.getenv("HTTP_TIMEOUT", "30"))
REFRESH_FLOW      = os.getenv("REFRESH_FLOW", "oauth").lower()  # "oauth" (default) or "partner"

TOKENS_FILE       = os.getenv("TOKENS_FILE", "tokens.json")

# Products endpoint (list/search). We'll scan A–Z to gather items.
PRODUCTS_SEARCH_URL = f"{BASE}/v1/Portfolio/Products/Search"

def save_tokens(data: Dict[str, Any]):
    with open(TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"[tokens] saved -> {TOKENS_FILE}")

def load_tokens() -> Dict[str, Any]:
    if not os.path.exists(TOKENS_FILE):
        return {}
    with open(TOKENS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def oauth_authorize_and_exchange() -> Dict[str, Any]:
    """
    One-time interactive step:
     - spin up localhost server to capture ?code=...
     - open AUTHORIZE_URL
     - exchange code at TOKEN_URL (grant_type=authorization_code)
    """
    parsed = urlparse(REDIRECT_URI)
    host, port = parsed.hostname, parsed.port or 8000
    state = "state-" + str(int(time.time()))

    code_holder = {"code": None, "error": None}

    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            qs = parse_qs(urlparse(self.path).query)
            if "error" in qs:
                code_holder["error"] = qs.get("error", ["unknown"])[0]
                self._ok("Authorization failed. You can close this window.")
                return
            code = qs.get("code", [None])[0]
            st   = qs.get("state", [None])[0]
            if not code or st != state:
                self._ok("Missing/invalid code or state. You can close this window.")
                return
            code_holder["code"] = code
            self._ok("Authorization successful! You can close this window.")

        def log_message(self, fmt, *args):  # silence server logs
            return

        def _ok(self, msg):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(msg.encode("utf-8"))

    httpd = HTTPServer((host, port), CallbackHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
        "state": state,
    }
    url = f"{AUTHORIZE_URL}?{urlencode(params)}"
    print("[oauth] Opening browser for consent…")
    webbrowser.open(url)

    # wait for code
    for _ in range(600):  # up to ~60s
        if code_holder["code"] or code_holder["error"]:
            break
        time.sleep(0.1)
    httpd.shutdown()

    if code_holder["error"]:
        raise SystemExit(f"[oauth] Authorization error: {code_holder['error']}")
    if not code_holder["code"]:
        raise SystemExit("[oauth] Timed out waiting for authorization code")

    # Exchange code for tokens
    data = {
        "grant_type": "authorization_code",
        "code": code_holder["code"],
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    headers = {"Accept": "application/json"}
    resp = requests.post(TOKEN_URL, data=data, headers=headers, timeout=TIMEOUT)
    if resp.status_code >= 400:
        raise SystemExit(f"[oauth] Token exchange failed: {resp.status_code} {resp.reason}\n{resp.text[:500]}")
    tokens = resp.json()
    if not tokens.get("refresh_token"):
        print("[warn] No refresh_token in token response; check your app's scopes/flow.")
    save_tokens(tokens)
    return tokens

def get_access_token(tokens: Dict[str, Any]) -> Dict[str, Any]:
    """
    Use refresh_token to get a fresh access_token.
    Supports two modes:
      - Standard OAuth: POST to TOKEN_URL with grant_type=refresh_token
      - Partner flow:   GET  {BASE}/v1/Security/Token with special headers
    """
    refresh = tokens.get("refresh_token")
    if not refresh:
        raise SystemExit("[tokens] No refresh_token available. Run the one-time authorize step first.")

    if REFRESH_FLOW == "partner":
        # Partner Refresh Token flow (if your tenant requires it)
        url = f"{BASE}/v1/Security/Token"
        headers = {
            "Authorization": f"Bearer {refresh}",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "Accept": "application/json"
        }
        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        if r.status_code >= 400:
            raise SystemExit(f"[partner-refresh] Failed: {r.status_code} {r.reason}\n{r.text[:500]}")
        data = r.json()
        if not data.get("access_token"):
            raise SystemExit(f"[partner-refresh] No access_token in response: {data}")
        # Some tenants rotate refresh_token too; persist if present
        if data.get("refresh_token"):
            tokens["refresh_token"] = data["refresh_token"]
        tokens["access_token"] = data["access_token"]
        save_tokens(tokens)
        return tokens

    # Default: Standard OAuth refresh
    form = {
        "grant_type": "refresh_token",
        "refresh_token": refresh,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    headers = {"Accept": "application/json"}
    r = requests.post(TOKEN_URL, data=form, headers=headers, timeout=TIMEOUT)
    if r.status_code >= 400:
        raise SystemExit(f"[oauth-refresh] Failed: {r.status_code} {r.reason}\n{r.text[:500]}")
    data = r.json()
    if not data.get("access_token"):
        raise SystemExit(f"[oauth-refresh] No access_token in response: {data}")
    # Persist latest tokens (in case refresh_token rotated)
    tokens.update({k: v for k, v in data.items() if k in ("access_token", "refresh_token")})
    save_tokens(tokens)
    return tokens

def pick(v: Dict[str, Any], *keys):
    for k in keys:
        if k in v and v[k] is not None:
            return v[k]
    return ""

def fetch_products(access_token: str) -> List[Dict[str, Any]]:
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}

    # Try a "no-term" pull; if empty, A–Z scan with ?search=
    items: List[Dict[str, Any]] = []
    r = requests.get(PRODUCTS_SEARCH_URL, headers=headers, params={"isActive": "true", "top": "200"}, timeout=TIMEOUT)
    if r.status_code == 200:
        payload = r.json()
        if isinstance(payload, list):
            items = payload
        elif isinstance(payload, dict):
            for k in ("items", "data", "results", "value"):
                if isinstance(payload.get(k), list):
                    items = payload[k]
                    break

    if not items:
        seen = set()
        results: List[Dict[str, Any]] = []
        for ch in list(string.ascii_uppercase) + list(string.digits):
            params = {"search": ch, "isActive": "true", "top": "200"}
            r = requests.get(PRODUCTS_SEARCH_URL, headers=headers, params=params, timeout=TIMEOUT)
            if r.status_code == 401:
                raise SystemExit("401 during product search — access_token likely expired.")
            if r.status_code >= 400:
                time.sleep(0.1)
                continue
            payload = r.json()
            arr = []
            if isinstance(payload, list):
                arr = payload
            elif isinstance(payload, dict):
                for k in ("items", "data", "results", "value"):
                    if isinstance(payload.get(k), list):
                        arr = payload[k]; break
            for p in arr:
                key = (str(p.get("productId") or "").strip()
                       or (p.get("name") or "").strip().upper())
                if key and key not in seen:
                    seen.add(key)
                    results.append(p)
            time.sleep(0.08)
        items = results

    # Project minimal columns for now
    projected = []
    for p in items:
        projected.append({
            "productId": pick(p, "productId", "id", "productID", "securityId"),
            "name":      pick(p, "name", "productName", "securityName")
        })
    return projected

def write_csv(rows: List[Dict[str, Any]], path: str):
    cols = ["productId", "name"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in cols})

def main():
    if not (CLIENT_ID and CLIENT_SECRET):
        raise SystemExit("Set ORION_CLIENT_ID and ORION_CLIENT_SECRET in .env")

    tokens = load_tokens()
    # If we don't yet have a refresh_token, do the one-time authorize
    if not tokens.get("refresh_token"):
        print("[setup] No refresh_token found; starting one-time OAuth...")
        tokens = oauth_authorize_and_exchange()

    # Now use the refresh_token to get a fresh access_token
    tokens = get_access_token(tokens)
    access_token = tokens["access_token"]

    products = fetch_products(access_token)
    print(f"Fetched {len(products)} products.")
    write_csv(products, OUTFILE)
    print(f"Saved to {OUTFILE}")

if __name__ == "__main__":
    main()
