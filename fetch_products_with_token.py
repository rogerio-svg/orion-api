# fetch_products_with_token.py
import os
import csv
import time
import string
from typing import List, Dict, Any

import requests
from dotenv import load_dotenv

# -------------------- Config --------------------
load_dotenv()  # reads .env if present

# Prefer ORION_BASE if provided; otherwise we'll auto-resolve
ENV_BASE = (os.getenv("ORION_BASE") or "").rstrip("/")
BASES_TO_TRY = [b for b in [ENV_BASE, "https://api.orionadvisor.com/api/v1", "https://testapi.orionadvisor.com/api/v1"] if b]

OUTFILE = os.getenv("OUTPUT_FILE", "products_swagger_token.csv")
TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "30"))

TOKEN = os.getenv("ORION_TOKEN") or ""

# Desired output fields (with common variants, incl. QSIP)
FIELD_CANDIDATES = {
    "productId": ["productId", "id", "productID", "securityId"],
    "name":      ["name", "productName", "securityName"],
    "ticker":    ["ticker", "symbol"],
    "qsip":      ["qsip", "QSIP", "qSip", "qsipCode"],
    "cusip":     ["cusip", "CUSIP"],
    "isin":      ["isin", "ISIN"],
}

# -------------------- Helpers --------------------
def pick_first(obj: Dict[str, Any], candidates: List[str]):
    for k in candidates:
        if isinstance(obj, dict) and k in obj and obj[k] is not None:
            return obj[k]
    return None

def project_product(p: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "productId": pick_first(p, FIELD_CANDIDATES["productId"]) or "",
        "name":      pick_first(p, FIELD_CANDIDATES["name"]) or "",
        "ticker":    pick_first(p, FIELD_CANDIDATES["ticker"]) or "",
        "qsip":      pick_first(p, FIELD_CANDIDATES["qsip"]) or "",
        "cusip":     pick_first(p, FIELD_CANDIDATES["cusip"]) or "",
        "isin":      pick_first(p, FIELD_CANDIDATES["isin"]) or "",
    }

def resolve_base(headers: Dict[str, str]) -> str:
    """
    Try the provided base(s) and pick the first that responds as expected.
    We probe /Trading/Products/Search/A to avoid the no-term 404.
    Accept 200/204/400/404 as "endpoint exists"; reject 401 (bad token for that env).
    """
    for base in BASES_TO_TRY:
        try:
            probe = f"{base}/Trading/Products/Search/A"
            r = requests.get(probe, headers=headers, timeout=TIMEOUT)
            if r.status_code in (200, 204, 400, 404):
                return base
            # If unauthorized for this base, try the next one
            if r.status_code in (401, 403):
                continue
        except requests.RequestException:
            continue
    raise SystemExit("Could not find a working API base for this token (tried prod & test). "
                     "Paste a fresh token or set ORION_BASE explicitly in .env.")

def fetch_no_term(products_search: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Try GET /Trading/Products/Search (no search term).
    Some tenants return 404 for this — treat as 'no results' so we can fall back.
    """
    r = requests.get(products_search, headers=headers, timeout=TIMEOUT)
    if r.status_code == 401:
        raise SystemExit("401 Unauthorized — the token is invalid or expired. Paste a fresh Swagger token.")
    if r.status_code == 404:
        return []
    r.raise_for_status()
    data = r.json() if "application/json" in r.headers.get("content-type", "") else {}
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        return data["items"]
    if isinstance(data, list):
        return data
    for k in ("data", "results", "value"):
        if isinstance(data, dict) and isinstance(data.get(k), list):
            return data[k]
    return []

def fetch_alpha_scan(base: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Scan A–Z and 0–9 via /Trading/Products/Search/{term}
    and de-duplicate results. Resilient to sporadic 4xx per letter.
    """
    seen = set()
    results: List[Dict[str, Any]] = []
    chars = list(string.ascii_uppercase) + list(string.digits)
    for ch in chars:
        url = f"{base}/Trading/Products/Search/{requests.utils.quote(ch)}"
        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        if r.status_code == 401:
            raise SystemExit("401 Unauthorized — the token is invalid or expired. Paste a fresh Swagger token.")
        if r.status_code >= 400:
            time.sleep(0.15)
            continue
        payload = r.json() if "application/json" in r.headers.get("content-type", "") else []
        if isinstance(payload, dict) and isinstance(payload.get("items"), list):
            arr = payload["items"]
        elif isinstance(payload, list):
            arr = payload
        else:
            arr = []
        for p in arr:
            pid = str(p.get("productId") or "")
            key = pid or f"{(p.get('ticker') or '').upper()}|{(p.get('name') or '').upper()}"
            if key and key not in seen:
                seen.add(key)
                results.append(p)
        time.sleep(0.12)
    return results

def save_csv(rows: List[Dict[str, Any]], path: str) -> None:
    cols = ["productId", "name", "ticker", "qsip", "cusip", "isin"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in cols})

# -------------------- Main --------------------
def main():
    global TOKEN
    if not TOKEN:
        TOKEN = input("Paste your Orion Swagger token (Bearer token): ").strip()
        if not TOKEN:
            raise SystemExit("No token provided. Set ORION_TOKEN in .env or paste when prompted.")

    headers = {"Authorization": f"Bearer {TOKEN}", "Accept": "application/json"}

    base = resolve_base(headers)
    products_search = f"{base}/Trading/Products/Search"
    print(f"Using base: {base}")

    # Try the 'no-term' endpoint first; if empty/404, fall back to A–Z scan
    try:
        raw = fetch_no_term(products_search, headers)
        if not raw:
            raw = fetch_alpha_scan(base, headers)
    except requests.HTTPError as e:
        raise SystemExit(f"HTTP error: {e}")
    except Exception as e:
        raise SystemExit(f"Error fetching products: {e}")

    projected = [project_product(p) for p in raw if isinstance(p, dict)]
    save_csv(projected, OUTFILE)

    print(f"Fetched {len(projected)} products → {OUTFILE}")
    for r in projected[:10]:
        print(r)

if __name__ == "__main__":
    main()
