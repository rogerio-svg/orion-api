import os
import sys
import csv
import time
import base64
import string
from typing import Dict, Any, List, Optional, Set

import requests
from dotenv import load_dotenv

# ---------------- Config ----------------
load_dotenv()  # reads .env if present

BASE = os.getenv("ORION_BASE", "https://api.orionadvisor.com/api/v1").rstrip("/")
USERNAME = os.getenv("ORION_USERNAME", "")
PASSWORD = os.getenv("ORION_PASSWORD", "")
OUTFILE = os.getenv("OUTPUT_FILE", "products.csv")
TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "30"))

TOKEN_URL = f"{BASE}/Security/Token"  # Token endpoint (short-lived bearer) :contentReference[oaicite:4]{index=4}

# Products simple search endpoint (returns your accessible products)
PRODUCTS_SEARCH = f"{BASE}/Trading/Products/Search"  # • /Search (no term) • /Search/{term}

# Desired output fields with common fallbacks
FIELD_MAP = {
    "productId": ["productId", "id", "productID", "securityId"],
    "name":      ["name", "productName", "securityName"],
    "ticker":    ["ticker", "symbol"],
    "cusip":     ["cusip", "CUSIP"],
    "isin":      ["isin", "ISIN"],
}

# ---------------- Auth helpers ----------------
def _extract_token(payload: Any) -> Optional[str]:
    """Try common property names returned by various Orion tenants."""
    if isinstance(payload, dict):
        for key in ("access_token", "token", "Token", "value", "bearerToken", "BearerToken"):
            v = payload.get(key)
            if v:
                return str(v)
    if isinstance(payload, str) and payload.strip():
        return payload.strip()
    return None

def _log_err(prefix: str, r: requests.Response) -> None:
    body = r.text[:800] if r.text else ""
    print(f"{prefix} -> {r.status_code} {r.reason}\n{body}\n", file=sys.stderr)

def get_token(username: str, password: str) -> str:
    """
    Try the common token flows Orion exposes under /v1/Security/Token:
      - POST JSON body { Username, Password }  (shown in Swagger) :contentReference[oaicite:5]{index=5}
      - GET with HTTP Basic Authorization header
      - POST form-encoded
    Returns a short-lived Bearer token (expected by Orion). 
    """
    # 1) POST JSON
    try:
        r = requests.post(
            TOKEN_URL,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            json={"Username": username, "Password": password},
            timeout=TIMEOUT,
        )
        if r.status_code < 400:
            token = _extract_token(r.json() if "application/json" in r.headers.get("content-type", "") else r.text)
            if token:
                print("Token acquired (POST JSON).")
                return token
        else:
            _log_err("Token POST(JSON) failed", r)
    except requests.RequestException as e:
        print(f"Token POST(JSON) error: {e}", file=sys.stderr)

    # 2) GET with HTTP Basic
    try:
        basic = base64.b64encode(f"{username}:{password}".encode()).decode()
        r = requests.get(
            TOKEN_URL,
            headers={"Accept": "application/json", "Authorization": f"Basic {basic}"},
            timeout=TIMEOUT,
        )
        if r.status_code < 400:
            token = _extract_token(r.json() if "application/json" in r.headers.get("content-type", "") else r.text)
            if token:
                print("Token acquired (GET Basic).")
                return token
        else:
            _log_err("Token GET(Basic) failed", r)
    except requests.RequestException as e:
        print(f"Token GET(Basic) error: {e}", file=sys.stderr)

    # 3) POST form-encoded
    try:
        r = requests.post(
            TOKEN_URL,
            headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
            data={"Username": username, "Password": password},
            timeout=TIMEOUT,
        )
        if r.status_code < 400:
            token = _extract_token(r.json() if "application/json" in r.headers.get("content-type", "") else r.text)
            if token:
                print("Token acquired (POST form).")
                return token
        else:
            _log_err("Token POST(form) failed", r)
    except requests.RequestException as e:
        print(f"Token POST(form) error: {e}", file=sys.stderr)

    # If your tenant enforces 2FA, we may need an extra step under Security/Token (e.g., SendTwoFactorCode). :contentReference[oaicite:7]{index=7}
    raise SystemExit(
        "Could not get a token. If your Swagger login works, confirm: "
        "• ORION_BASE matches that Swagger environment; "
        "• this user is API-enabled; "
        "• whether 2FA is enforced (we can wire the code step)."
    )

# ---------------- Products fetch ----------------
def _pick_first(obj: Dict[str, Any], keys: List[str]) -> Any:
    for k in keys:
        if k in obj and obj[k] is not None:
            return obj[k]
    return None

def _project(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "productId": _pick_first(row, FIELD_MAP["productId"]),
        "name":      _pick_first(row, FIELD_MAP["name"]),
        "ticker":    _pick_first(row, FIELD_MAP["ticker"]),
        "cusip":     _pick_first(row, FIELD_MAP["cusip"]),
        "isin":      _pick_first(row, FIELD_MAP["isin"]),
    }

def _get_products_simple(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    # Try no-term search first (many tenants allow it)
    r = requests.get(PRODUCTS_SEARCH, headers=headers, timeout=TIMEOUT)
    if r.status_code == 204:
        return []
    if r.status_code >= 400:
        _log_err("Products Search (no term) failed", r)
        return []
    data = r.json() if "application/json" in r.headers.get("content-type", "") else []
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        return data["items"]
    if isinstance(data, list):
        return data
    for key in ("data", "results", "value"):
        if isinstance(data, dict) and isinstance(data.get(key), list):
            return data[key]
    return []

def _alphabet_scan(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    seen: Set[str] = set()
    results: List[Dict[str, Any]] = []
    for ch in list(string.ascii_uppercase) + list(string.digits):
        url = f"{PRODUCTS_SEARCH}/{requests.utils.quote(ch)}"
        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        if r.status_code >= 400:
            # be resilient; keep scanning
            time.sleep(0.2)
            continue
        batch = r.json() if "application/json" in r.headers.get("content-type", "") else []
        if isinstance(batch, dict) and isinstance(batch.get("items"), list):
            arr = batch["items"]
        elif isinstance(batch, list):
            arr = batch
        else:
            arr = []
        for p in arr:
            pid = str(p.get("productId") or "").strip()
            key = pid or f"{(p.get('ticker') or '').upper()}|{(p.get('name') or '').upper()}"
            if key and key not in seen:
                seen.add(key)
                results.append(p)
        time.sleep(0.2)
    return results

def fetch_products(token: str) -> List[Dict[str, Any]]:
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    data = _get_products_simple(headers)
    if not data:
        data = _alphabet_scan(headers)
    return [_project(p) for p in data if p]

def write_csv(rows: List[Dict[str, Any]], path: str) -> None:
    cols = ["productId", "name", "ticker", "cusip", "isin"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in cols})

def main():
    if not USERNAME or not PASSWORD:
        raise SystemExit("Set ORION_USERNAME and ORION_PASSWORD (via .env)")

    print(f"Base: {BASE}")
    token = get_token(USERNAME, PASSWORD)  # short-lived by design (refresh each run) 
    products = fetch_products(token)
    print(f"Fetched {len(products)} products.")
    write_csv(products, OUTFILE)
    print(f"Saved to {OUTFILE}")

if __name__ == "__main__":
    main()
