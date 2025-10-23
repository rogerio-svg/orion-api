import os, sys, csv, time, string, json
from typing import Dict, Any, List, Optional

import requests
from dotenv import load_dotenv

load_dotenv()

BASE = os.getenv("ORION_BASE", "https://api.orionadvisor.com/api").rstrip("/")
CLIENT_ID = os.getenv("ORION_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("ORION_CLIENT_SECRET", "")
OUTFILE = os.getenv("OUTPUT_FILE", "products.csv")
TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "30"))
TOKENS_FILE = os.getenv("TOKENS_FILE", "tokens.json")

SECURITY_TOKEN_URL = f"{BASE}/v1/Security/Token"

# Primary products endpoint (most tenants)
PORTFOLIO_PRODUCTS_SEARCH = f"{BASE}/v1/Portfolio/Products/Search"
# Fallback for tenants exposing "Trading"
TRADING_PRODUCTS_SEARCH = f"{BASE}/v1/Trading/Products/Search"

def save_tokens(data: Dict[str, Any]) -> None:
    try:
        with open(TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[tokens] saved -> {TOKENS_FILE}")
    except Exception as e:
        print(f"[warn] could not save tokens file: {e}", file=sys.stderr)

def load_tokens() -> Dict[str, Any]:
    if not os.path.exists(TOKENS_FILE):
        return {}
    try:
        with open(TOKENS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def partner_get_tokens() -> Dict[str, Any]:
    """
    Partner Refresh Flow (no browser):
    Call /v1/Security/Token with client credentials to obtain an access_token
    (and refresh_token if your tenant issues one).
    We try JSON first, then form-encoded as a fallback.
    """
    if not CLIENT_ID or not CLIENT_SECRET:
        raise SystemExit("Set ORION_CLIENT_ID and ORION_CLIENT_SECRET in .env")

    payload = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }

    # Try JSON
    try:
        r = requests.post(SECURITY_TOKEN_URL,
                          headers={"Accept": "application/json",
                                   "Content-Type": "application/json"},
                          json=payload, timeout=TIMEOUT)
        if r.status_code < 400:
            data = r.json()
            if "access_token" in data:
                return data
            # some tenants might return token under a different casing
            if "accessToken" in data:
                data["access_token"] = data["accessToken"]
                return data
        else:
            # fall through to form if JSON failed
            print(f"[auth] JSON token call failed: {r.status_code} {r.reason}", file=sys.stderr)
            # print body preview for debugging
            if r.text:
                print(r.text[:300], file=sys.stderr)
    except requests.RequestException as e:
        print(f"[auth] JSON token call error: {e}", file=sys.stderr)

    # Try x-www-form-urlencoded
    try:
        r = requests.post(SECURITY_TOKEN_URL,
                          headers={"Accept": "application/json",
                                   "Content-Type": "application/x-www-form-urlencoded"},
                          data=payload, timeout=TIMEOUT)
        if r.status_code < 400:
            data = r.json()
            if "access_token" in data:
                return data
            if "accessToken" in data:
                data["access_token"] = data["accessToken"]
                return data
        else:
            print(f"[auth] FORM token call failed: {r.status_code} {r.reason}", file=sys.stderr)
            if r.text:
                print(r.text[:300], file=sys.stderr)
    except requests.RequestException as e:
        print(f"[auth] FORM token call error: {e}", file=sys.stderr)

    raise SystemExit("Could not obtain tokens from /v1/Security/Token. "
                     "Verify ORION_BASE, client_id/secret, and that Partner flow is enabled for your app.")

def ensure_access_token() -> Dict[str, Any]:
    """
    If we already have a tokens.json with a still-working access_token, use it.
    Otherwise call partner_get_tokens() to get a new one and persist.
    (If your tenant also returns/rotates a refresh_token, we store it too.)
    """
    tokens = load_tokens()
    access_token = tokens.get("access_token")
    if access_token:
        # Optionally, we could validate it with a tiny probe; for simplicity, we proceed.
        return tokens

    tokens = partner_get_tokens()
    save_tokens(tokens)
    return tokens

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

def products_no_term(headers: Dict[str, str], base_url: str) -> List[Dict[str, Any]]:
    r = requests.get(base_url, headers=headers, params={"isActive": "true", "top": "200"}, timeout=TIMEOUT)
    if r.status_code in (401, 403):
        raise SystemExit("Unauthorized while fetching products — token likely invalid/expired.")
    if r.status_code == 404:
        return []
    r.raise_for_status()
    return parse_items(r.json())

def products_alpha_scan(headers: Dict[str, str], base_url: str) -> List[Dict[str, Any]]:
    seen = set()
    out: List[Dict[str, Any]] = []
    for ch in list(string.ascii_uppercase) + list(string.digits):
        r = requests.get(base_url, headers=headers,
                         params={"search": ch, "isActive": "true", "top": "200"},
                         timeout=TIMEOUT)
        if r.status_code in (401, 403):
            raise SystemExit("Unauthorized during A–Z scan — token likely invalid/expired.")
        if r.status_code >= 400:
            time.sleep(0.1)
            continue
        arr = parse_items(r.json())
        for p in arr:
            key = str(p.get("productId") or "").strip() or (p.get("name") or "").strip().upper()
            if key and key not in seen:
                seen.add(key)
                out.append(p)
        time.sleep(0.07)
    return out

def fetch_products_minimal(access_token: str) -> List[Dict[str, Any]]:
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}

    # Try Portfolio/Products/Search first
    base1 = PORTFOLIO_PRODUCTS_SEARCH
    try:
        items = products_no_term(headers, base1)
        if not items:
            items = products_alpha_scan(headers, base1)
        if items:
            return [{"productId": pick(p, "productId", "id", "productID", "securityId"),
                     "name": pick(p, "name", "productName", "securityName")} for p in items]
    except requests.HTTPError:
        pass  # fall back to Trading

    # Fallback: Trading/Products/Search
    base2 = TRADING_PRODUCTS_SEARCH
    try:
        # No-term variant may 404 on some tenants; we'll just A–Z scan
        items = products_alpha_scan(headers, base2)
        return [{"productId": pick(p, "productId", "id", "productID", "securityId"),
                 "name": pick(p, "name", "productName", "securityName")} for p in items]
    except requests.HTTPError as e:
        raise SystemExit(f"Products fetch failed: {e}")

def write_csv(rows: List[Dict[str, Any]], path: str) -> None:
    cols = ["productId", "name"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in cols})

def main():
    print(f"Base: {BASE}")
    tokens = ensure_access_token()
    at = tokens.get("access_token")
    if not at:
        # Some tenants return token under accessToken
        at = tokens.get("accessToken")
    if not at:
        raise SystemExit("No access_token in tokens. Check your credentials/tenant configuration.")

    rows = fetch_products_minimal(at)
    print(f"Fetched {len(rows)} products.")
    write_csv(rows, OUTFILE)
    print(f"Saved to {OUTFILE}")

if __name__ == "__main__":
    main()
