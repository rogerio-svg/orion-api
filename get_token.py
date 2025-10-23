import requests
import webbrowser
import threading  # Import threading
import time       # Import time
import json
from urllib.parse import urlencode, urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import os

# Variaveis
CLIENT_ID = '2145'
CLIENT_SECRET = '35b51998-3b61-4b3b-afff-c1269511c670'
REDIRECT_URI = 'http://localhost:8000/callback'
STATE = 'secure_random_state'
OAUTH_BASE_URL = 'https://api.orionadvisor.com/api'
TOKEN_FILE = 'tokens.json'


# OAuth
class OAuthCallbackHandler(BaseHTTPRequestHandler):
    # (No changes needed inside this class)
    def do_GET(self):
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        if 'error' in query_params:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"OAuth Error: " + query_params['error'][0].encode())
            return
        code = query_params.get('code', [None])[0]
        returned_state = query_params.get('state', [''])[0]
        if returned_state != STATE or not code:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid request.")
            return
        print(f"Received authorization code: {code}")
        token_url = f"{OAUTH_BASE_URL}/v1/Security/Token"
        token_params = {
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': CLIENT_ID,
            'redirect_uri': REDIRECT_URI,
            'response_type': 'code',
            'client_secret': CLIENT_SECRET
        }
        print("Requesting tokens from OAuth server...")
        response = requests.post(token_url, params=token_params)
        if response.status_code != 200:
            self.send_response(500)
            self.end_headers()
            error_message = f"Failed to get token: {response.status_code} {response.text}"
            print(error_message)
            self.wfile.write(error_message.encode())
            return
        tokens = response.json()
        with open(TOKEN_FILE, 'w') as f:
            json.dump(tokens, f)
        print("✅ Tokens saved to tokens.json")
        print("Access Token:", tokens['access_token'])
        print("Refresh Token:", tokens['refresh_token'])
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"<h1>Authorization Successful!</h1><p>You can close this window.</p>")
        # Use a thread to shut down the server
        threading.Thread(target=self.server.shutdown).start()


# Funcao de rodar o servidor local porta 8000
def run_local_server():
    server_address = ('localhost', 8000)  # Be explicit with 'localhost'
    httpd = HTTPServer(server_address, OAuthCallbackHandler)
    print("Starting local server at http://localhost:8000/callback ...")
    httpd.serve_forever()

print("Starting server thread...")
server_thread = threading.Thread(target=run_local_server)
server_thread.daemon = True  # This allows the main program to exit
server_thread.start()

time.sleep(1) 

auth_params = {
    'response_type': 'code',
    'client_id': CLIENT_ID,
    'redirect_uri': REDIRECT_URI,
    'state': STATE
}
authorization_url = f"{OAUTH_BASE_URL}/oauth/?" + urlencode(auth_params)

# Autorizacao
print("Opening browser for user authorization...")
webbrowser.open(authorization_url)