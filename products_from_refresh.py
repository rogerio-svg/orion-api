import os, json, csv, time, string, sys
from typing import Dict, Any, List
import requests

# ---- Config ----
BASE = os.getenv("ORION_BASE", "https://api.orionadvisor.com/api").rstrip("/")
API_BASE = os.getenv("ORION_API_BASE", f"{BASE}/v1").rstrip("/")
CLIENT_ID = "2145"
CLIENT_SECRET = "35b51998-3b61-4b3b-afff-c1269511c670sh"
TOKENS_FILE = os.getenv("TOKENS_FILE", "tokens.json")
OUTFILE = os.getenv("OUTPUT_FILE", "products.csv")
TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "30"))

SECURITY_TOKEN_URL = f"{BASE}/v1/Security/Token"
PORTFOLIO_PRODUCTS_SEARCH = f"{API_BASE}/Portfolio/Products/Search"
TRADING_PRODUCTS_SEARCH   = f"{API_BASE}/Trading/Products/Search"

def load_tokens() -> Dict[str, Any]:
    if not os.path.exists(TOKENS_FILE):
        raise SystemExit(f"tokens.json not found. Run your one-time browser script first to create {TOKENS_FILE}.")
    with open(TOKENS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_tokens(tokens: Dict[str, Any]) -> None:
    with open(TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2)
    print(f"[tokens] saved -> {TOKENS_FILE}")

def refresh_access_token(tokens: Dict[str, Any]) -> Dict[str, Any]:
    """
    Try BOTH common refresh styles used by Orion tenants:

    A) OAuth-style (POST form):
       POST {BASE}/v1/Security/Token
         grant_type=refresh_token
         refresh_token=...
         client_id=...
         client_secret=...

    B) Partner header-style (GET with refresh token as Bearer):
       GET {BASE}/v1/Security/Token
         Headers:
           Authorization: Bearer <refresh_token>
           client_id: <id>
           client_secret: <secret>
    """
    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        raise SystemExit("No refresh_token in tokens.json. Run the one-time browser flow again.")

    # ---- A) OAuth-style POST (form-encoded) ----
    form = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    try:
        r = requests.post(
            SECURITY_TOKEN_URL,
            data=form,
            headers={"Accept": "application/json"},
            timeout=TIMEOUT,
        )
        if r.status_code < 400:
            data = r.json()
            if "access_token" in data:
                tokens.update({k: data[k] for k in ("access_token",) if k in data})
                # Some tenants rotate refresh_token
                if "refresh_token" in data and data["refresh_token"]:
                    tokens["refresh_token"] = data["refresh_token"]
                save_tokens(tokens)
                return tokens
        else:
            # print brief hint and try the header-style next
            print(f"[refresh POST] {r.status_code} {r.reason} | {r.text[:180]}", file=sys.stderr)
    except requests.RequestException as e:
        print(f"[refresh POST] {e}", file=sys.stderr)

    # ---- B) Partner header-style GET ----
    try:
        r = requests.get(
            SECURITY_TOKEN_URL,
            headers={
                "Authorization": f"Bearer {refresh_token}",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "Accept": "application/json",
            },
            timeout=TIMEOUT,
        )
        if r.status_code < 400:
            data = r.json()
            if "access_token" in data:
                tokens.update({k: data[k] for k in ("access_token",) if k in data})
                if "refresh_token" in data and data["refresh_token"]:
                    tokens["refresh_token"] = data["refresh_token"]
                save_tokens(tokens)
                return tokens
        else:
            print(f"[refresh GET] {r.status_code} {r.reason} | {r.text[:180]}", file=sys.stderr)
    except requests.RequestException as e:
        print(f"[refresh GET] {e}", file=sys.stderr)

    raise SystemExit("Could not refresh access token. If your refresh token was revoked/expired, "
                     "re-run the one-time browser flow to obtain a new one.")

def pick(v: Dict[str, Any], *keys):
    for k in keys:
        if k in v and v[k] is not None:
            return v[k]
    return ""

def parse_items(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for k in ("items", "data", "results", "value"):
            if isinstance(payload.get(k), list):
                return payload[k]
    return []

def products_no_term(headers: Dict[str, str], url: str) -> List[Dict[str, Any]]:
    r = requests.get(url, headers=headers, params={"isActive": "true", "top": "200"}, timeout=TIMEOUT)
    if r.status_code in (401, 403):
        raise SystemExit("Unauthorized while fetching products — token invalid or insufficient scope.")
    if r.status_code == 404:
        return []
    r.raise_for_status()
    return parse_items(r.json())

def products_alpha_scan(headers: Dict[str, str], url: str) -> List[Dict[str, Any]]:
    import string as _s
    seen = set()
    out: List[Dict[str, Any]] = []
    for ch in list(_s.ascii_uppercase) + list(_s.digits):
        r = requests.get(url, headers=headers,
                         params={"search": ch, "isActive": "true", "top": "200"},
                         timeout=TIMEOUT)
        if r.status_code in (401, 403):
            raise SystemExit("Unauthorized during A–Z scan — token invalid or insufficient scope.")
        if r.status_code >= 400:
            time.sleep(0.05)
            continue
        arr = parse_items(r.json())
        for p in arr:
            key = str(p.get("productId") or "").strip() or (p.get("name") or "").strip().upper()
            if key and key not in seen:
                seen.add(key)
                out.append(p)
        time.sleep(0.03)
    return out

def fetch_products_minimal(access_token: str) -> List[Dict[str, Any]]:
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    # Try Portfolio first; fall back to Trading
    try:
        items = products_no_term(headers, PORTFOLIO_PRODUCTS_SEARCH)
        if not items:
            items = products_alpha_scan(headers, PORTFOLIO_PRODUCTS_SEARCH)
        if items:
            return [{"productId": pick(p, "productId", "id", "productID", "securityId"),
                     "name": pick(p, "name", "productName", "securityName")} for p in items]
    except requests.HTTPError:
        pass
    items = products_alpha_scan(headers, TRADING_PRODUCTS_SEARCH)
    return [{"productId": pick(p, "productId", "id", "productID", "securityId"),
             "name": pick(p, "name", "productName", "securityName")} for p in items]

def write_csv(rows: List[Dict[str, Any]], path: str) -> None:
    cols = ["productId", "name"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in cols})

def main():
    print("Base:", BASE)
    print("API: ", API_BASE)

    tokens = load_tokens()
    tokens = refresh_access_token(tokens)  # <- automatic, no browser
    access_token = tokens.get("access_token") or tokens.get("accessToken")
    if not access_token:
        raise SystemExit("No access_token after refresh.")

    rows = fetch_products_minimal(access_token)
    print(f"Fetched {len(rows)} products.")
    write_csv(rows, OUTFILE)
    print(f"Saved to {OUTFILE}")

if __name__ == "__main__":
    main()

