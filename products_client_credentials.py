import os, sys, csv, time, string, json
from typing import Dict, Any, List
import requests
from dotenv import load_dotenv

load_dotenv()

BASE_OAUTH = os.getenv("ORION_BASE_OAUTH", "https://api.orionadvisor.com/api").rstrip("/")
BASE_API   = os.getenv("ORION_BASE_API",   "https://api.orionadvisor.com/api/v1").rstrip("/")

CLIENT_ID     = os.getenv("ORION_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("ORION_CLIENT_SECRET", "")
OUTFILE       = os.getenv("OUTPUT_FILE", "products.csv")
TIMEOUT       = int(os.getenv("HTTP_TIMEOUT", "30"))

# OAuth endpoints (common variants)
OAUTH_TOKEN_URLS = [
    f"{BASE_OAUTH}/oauth/token",
    f"{BASE_OAUTH}/oauth2/token",
]

# Products endpoints (we try both)
PORTFOLIO_PRODUCTS_SEARCH = f"{BASE_API}/Portfolio/Products/Search"
TRADING_PRODUCTS_SEARCH   = f"{BASE_API}/Trading/Products/Search"

def token_via_client_credentials() -> Dict[str, Any]:
    """
    Try POST client_credentials on common OAuth token URLs.
    Form-encoded is the typical requirement.
    """
    if not CLIENT_ID or not CLIENT_SECRET:
        raise SystemExit("Set ORION_CLIENT_ID and ORION_CLIENT_SECRET in .env")

    form = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        # include scopes if your tenant requires them (ask Orion). Common: "read offline_access"
        # "scope": "read"
    }
    headers = {"Accept": "application/json"}

    last_err = ""
    for url in OAUTH_TOKEN_URLS:
        try:
            # form-encoded first (most common)
            r = requests.post(url, data=form, headers=headers, timeout=TIMEOUT)
            if r.status_code < 400:
                try:
                    data = r.json()
                except Exception:
                    data = {}
                # normalize keys if needed
                if "access_token" in data:
                    return data
                if "accessToken" in data:  # rare casing variants
                    data["access_token"] = data["accessToken"]
                    return data
                last_err = f"200-range but no access_token in response: {data}"
            else:
                last_err = f"{r.status_code} {r.reason} @ {url} | {r.text[:400]}"
        except requests.RequestException as e:
            last_err = f"{type(e).__name__}: {e} @ {url}"

        # try JSON payload as a fallback
        try:
            r = requests.post(url, json=form, headers={"Accept": "application/json",
                                                       "Content-Type": "application/json"}, timeout=TIMEOUT)
            if r.status_code < 400:
                try:
                    data = r.json()
                except Exception:
                    data = {}
                if "access_token" in data:
                    return data
                if "accessToken" in data:
                    data["access_token"] = data["accessToken"]
                    return data
                last_err = f"200-range but no access_token in response: {data}"
            else:
                last_err = f"{r.status_code} {r.reason} @ {url} | {r.text[:400]}"
        except requests.RequestException as e:
            last_err = f"{type(e).__name__}: {e} @ {url}"

    raise SystemExit(f"Client-credentials token failed. Last error: {last_err}\n"
                     f"Check ORION_BASE_OAUTH, client_id/secret, and that client_credentials is enabled.")

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
        raise SystemExit("Unauthorized while fetching products — token invalid or permissions missing.")
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
            raise SystemExit("Unauthorized during A–Z scan — token invalid or permissions missing.")
        if r.status_code >= 400:
            time.sleep(0.1)
            continue
        arr = parse_items(r.json())
        for p in arr:
            key = str(p.get("productId") or "").strip() or (p.get("name") or "").strip().upper()
            if key and key not in seen:
                seen.add(key)
                out.append(p)
        time.sleep(0.06)
    return out

def fetch_products_minimal(access_token: str) -> List[Dict[str, Any]]:
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}

    # Try Portfolio/Products/Search first
    try:
        items = products_no_term(headers, PORTFOLIO_PRODUCTS_SEARCH)
        if not items:
            items = products_alpha_scan(headers, PORTFOLIO_PRODUCTS_SEARCH)
        if items:
            return [{"productId": pick(p, "productId", "id", "productID", "securityId"),
                     "name": pick(p, "name", "productName", "securityName")} for p in items]
    except requests.HTTPError:
        pass  # fall back to Trading

    # Fallback: Trading/Products/Search
    try:
        items = products_alpha_scan(headers, TRADING_PRODUCTS_SEARCH)  # many tenants need {search}
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
    print("OAuth base:", BASE_OAUTH)
    print("API base:  ", BASE_API)

    tokens = token_via_client_credentials()
    at = tokens.get("access_token") or tokens.get("accessToken")
    if not at:
        raise SystemExit(f"No access_token in response: {tokens}")

    rows = fetch_products_minimal(at)
    print(f"Fetched {len(rows)} products.")
    write_csv(rows, OUTFILE)
    print(f"Saved to {OUTFILE}")

if __name__ == "__main__":
    main()
