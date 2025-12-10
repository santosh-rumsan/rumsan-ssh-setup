#!/usr/bin/env python3
"""
Google OAuth Login with Implicit Flow (ID Token)
Uses response_type='id_token' to get ID token directly without code exchange
"""

import os
import json
import webbrowser
import requests
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import time
import base64
from datetime import datetime

# Configuration
SERVER_URL = "https://ceamyckytvqemsjijavg.supabase.co"
RUMSAN_FOLDER_PATH = os.path.expanduser("~/.rumsan/.ssh")
RUMSAN_SSH_ACCESS_FILE = os.path.join(RUMSAN_FOLDER_PATH, "ssh_access.sh")
REDIRECT_URI = "http://localhost:29670/callback"
GOOGLE_CLIENT_ID_URL = "https://raw.githubusercontent.com/santosh-rumsan/rumsan-ssh-setup/refs/heads/main/static/client_id"

# Global variables
id_token = None
server = None
selected_server = None
hosts_data = None


def get_api_headers():
    """Get standard API headers for authenticated requests"""
    return {
        'rs-google-token': id_token,
        'Content-Type': 'application/json'
    }


def decode_jwt_payload(token):
    """Decode JWT token payload (without verification)"""
    try:
        # Split the token
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        # Decode the payload (add padding if needed)
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception as e:
        print(f"[ERROR] Failed to decode token: {e}")
        return None


def is_token_expired(token):
    """Check if JWT token has expired"""
    payload = decode_jwt_payload(token)
    if not payload or 'exp' not in payload:
        return True
    
    exp_time = payload['exp']
    current_time = int(time.time())
    
    # Add 60 second buffer to ensure token is still usable
    return current_time > (exp_time - 60)


def get_token_expiry_timestamp(token):
    """Get the expiry timestamp of a JWT token"""
    payload = decode_jwt_payload(token)
    if payload and 'exp' in payload:
        return payload['exp']
    return None


def save_token_to_file(token):
    """Save ID token and expiry date to RUMSAN_SSH_ACCESS_FILE"""
    try:
        exp_timestamp = get_token_expiry_timestamp(token)
        if not exp_timestamp:
            print("[WARNING] Could not determine token expiry")
            return False
        
        # Create rumsan folder if not exists
        os.makedirs(RUMSAN_FOLDER_PATH, exist_ok=True)
        
        # Read existing content
        content = ""
        if os.path.exists(RUMSAN_SSH_ACCESS_FILE):
            with open(RUMSAN_SSH_ACCESS_FILE, 'r') as f:
                content = f.read()
        
        # Remove existing token and expiry lines
        lines = content.split('\n') if content else []
        lines = [line for line in lines if not line.startswith('GOOGLE_ID_TOKEN=') and not line.startswith('GOOGLE_TOKEN_EXPIRY=')]
        
        # Add new token and expiry
        lines.append(f'GOOGLE_ID_TOKEN="{token}"')
        lines.append(f'GOOGLE_TOKEN_EXPIRY="{exp_timestamp}"')
        
        new_content = '\n'.join(lines)
        
        with open(RUMSAN_SSH_ACCESS_FILE, 'w') as f:
            f.write(new_content)
        
        expiry_date = datetime.fromtimestamp(exp_timestamp).strftime('%Y-%m-%d %H:%M:%S')
        print(f"[OK] Token saved with expiry: {expiry_date}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to save token to file: {e}")
        return False


def load_token_from_file():
    """Load ID token from RUMSAN_SSH_ACCESS_FILE if still valid"""
    try:
        if not os.path.exists(RUMSAN_SSH_ACCESS_FILE):
            return None
        
        with open(RUMSAN_SSH_ACCESS_FILE, 'r') as f:
            content = f.read()
        
        # Parse token and expiry
        token = None
        expiry_timestamp = None
        
        lines = content.split('\n')
        for line in lines:
            if line.startswith('GOOGLE_ID_TOKEN='):
                token = line.split('=', 1)[1].strip('"')
            elif line.startswith('GOOGLE_TOKEN_EXPIRY='):
                expiry_timestamp = int(line.split('=', 1)[1].strip('"'))
        
        # Check if token exists and is not expired
        if token and expiry_timestamp:
            current_time = int(time.time())
            if current_time < (expiry_timestamp - 60):
                expiry_date = datetime.fromtimestamp(expiry_timestamp).strftime('%Y-%m-%d %H:%M:%S')
                print(f"[OK] Valid token found in file, expires: {expiry_date}")
                return token
            else:
                print("[INFO] Token has expired, need to re-authenticate")
        
        return None
    except Exception as e:
        print(f"[WARNING] Could not load token from file: {e}")
        return None


def generate_html_page(title, content):
    """Generate a consistent HTML page with styling"""
    return f"""
    <html>
    <head>
        <title>{title}</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                margin: 0;
                background: #f5f5f5;
            }}
            .container {{
                background: white;
                min-width: 300px;
                padding: 40px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                text-align: center;
            }}
            .logo {{
                width: 150px;
                height: 150px;
                margin: 0 auto 20px;
            }}
            h1 {{
                color: #333;
                margin-bottom: 30px;
            }}
            h2 {{
                color: #333;
                margin-bottom: 15px;
                font-size: 18px;
            }}
            p {{
                color: #666;
                line-height: 1.6;
            }}
            .code-block {{
                background: #f5f5f5;
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 12px;
                margin: 15px 0;
                font-family: 'Courier New', monospace;
                font-size: 14px;
                color: #333;
                overflow-x: auto;
            }}
            .info-text {{
                color: #666;
                font-size: 14px;
                margin-top: 15px;
            }}
            a {{
                color: #4CAF50;
                text-decoration: none;
            }}
            a:hover {{
                text-decoration: underline;
            }}
            select {{
                padding: 10px;
                font-size: 16px;
                border: 2px solid #ddd;
                border-radius: 4px;
                width: 100%;
                max-width: 300px;
                margin-bottom: 20px;
            }}
            button {{
                padding: 10px 30px;
                font-size: 16px;
                background: #4CAF50;
                color: white;
                border: none;
                border-radius: 4px;
                cursor: pointer;
            }}
            button:hover {{
                background: #45a049;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <img src="https://avatars.githubusercontent.com/u/102228984?s=1024&v=4" alt="Rumsan Logo" class="logo">
            {content}
        </div>
    </body>
    </html>
    """


class CallbackHandler(BaseHTTPRequestHandler):
    """Handles the OAuth callback and server selection"""
    
    def do_GET(self):
        global id_token
        
        # Parse the callback URL
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        
        # Handle server selection page request
        if parsed_url.path == '/server-selection':
            hosts = get_user_hosts(id_token)
            if hosts is None:
                html_content = generate_html_page(
                    "Error Loading Servers",
                    "<h1>Error Loading Servers</h1><p>Failed to fetch list of available servers.</p>"
                )
            else:
                html_content = show_server_selection_page(id_token, hosts)
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html_content.encode())
            return
        
        # Extract token from fragment using JavaScript and redirect with it as query param
        if 'id_token' not in query_params:
            # First request - send JavaScript to extract token from fragment
            html_content = generate_html_page(
                "Login Processing",
                "<h1>Processing your login...</h1><p>Please wait...</p><script>const fragment = window.location.hash.substring(1); const params = new URLSearchParams(fragment); const idToken = params.get('id_token'); if (idToken) { window.location.href = '/callback?id_token=' + encodeURIComponent(idToken); } else { document.body.innerHTML = '<div class=\"container\"><h1>Error</h1><p>Failed to retrieve authentication token. Please try again.</p></div>'; }</script>"
            )
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html_content.encode())
        else:
            # Second request - token is in query params
            id_token = query_params['id_token'][0]
            
            # Save token to file
            save_token_to_file(id_token)
            
            # Get SSH key ID
            file_path = RUMSAN_SSH_ACCESS_FILE
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Parse SSH_KEY
                ssh_key = None
                lines = content.split('\n')
                for line in lines:
                    if line.startswith('SSH_KEY='):
                        ssh_key = line.split('=', 1)[1].strip('"')
                        break
                
                if ssh_key:
                    # Make API call
                    url = SERVER_URL + "/functions/v1/user-query/get-ssh-key"
                    headers = get_api_headers()
                    data = {"public_key": ssh_key}
                    response = requests.post(url, headers=headers, json=data, timeout=10)
                    
                    if response.status_code == 200:
                        resp_data = response.json()
                        if resp_data.get('success'):
                            key_id = resp_data['data']['id']
                            # Remove any existing RS_KEY_ID line and add new one
                            lines = content.split('\n')
                            lines = [line for line in lines if not line.startswith('RS_KEY_ID=')]
                            lines.append(f'RS_KEY_ID="{key_id}"')
                            new_content = '\n'.join(lines)
                            with open(file_path, 'w') as f:
                                f.write(new_content)
                            print(f"[OK] SSH key ID retrieved: {key_id}")
                        else:
                            print("[ERROR] Failed to get SSH key ID: success false")
                    else:
                        # Check for specific error
                        if response.status_code == 500:
                            try:
                                error_data = response.json()
                                if error_data.get('error') == 'SSH key not found':
                                    html_content = generate_html_page(
                                        "SSH Key Not Registered",
                                        "<h1>SSH Key Not Registered</h1><p>Your SSH key is not registered in the server. Please go to <a href=\"https://office.rumsan.net\" target=\"_blank\">https://office.rumsan.net</a> to register it and try again.</p>"
                                    )
                                    self.send_response(200)
                                    self.send_header('Content-type', 'text/html')
                                    self.end_headers()
                                    self.wfile.write(html_content.encode())
                                    return
                            except:
                                pass
                        print(f"[ERROR] API call failed: {response.status_code} - {response.text}")
                else:
                    print("[ERROR] SSH_KEY not found in file")
            except FileNotFoundError:
                print(f"[ERROR] File not found: {file_path}")
            except Exception as e:
                print(f"[ERROR] Error processing SSH key: {e}")
            
            # Token processing complete, request server selection page
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html_content = generate_html_page(
                "Login Complete",
                "<h1>Login Successful!</h1><p>You can now close this window and the server selection will appear in a new window.</p>"
            )
            self.wfile.write(html_content.encode())
    
    def do_POST(self):
        global selected_server, hosts_data
        # Handle server selection
        if self.path == '/server-selected':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            data = json.loads(body.decode())
            
            selected_server_id = data.get('server_id')
            print(f"\n[OK] Selected server: {selected_server_id}")
            
            # Find the selected host and get its principal
            selected_host = None
            if hosts_data:
                host_list = []
                if isinstance(hosts_data, list):
                    host_list = hosts_data
                elif isinstance(hosts_data, dict):
                    if 'data' in hosts_data and isinstance(hosts_data['data'], list):
                        host_list = hosts_data['data']
                    elif 'hosts' in hosts_data and isinstance(hosts_data['hosts'], list):
                        host_list = hosts_data['hosts']
                    else:
                        host_list = [hosts_data] if hosts_data.get('name') or hosts_data.get('id') else []
                
                for host in host_list:
                    if isinstance(host, dict) and host.get('id') == selected_server_id:
                        selected_host = host
                        break
            
            if selected_host:
                server_principal = selected_host.get('principal', '')
                server_name = selected_host.get('name', '')
                print(f"[OK] Server principal: {server_principal}")
                print(f"[OK] Server name: {server_name}")
                
                # Update temp file with server ID, principal, and name
                try:
                    with open(RUMSAN_SSH_ACCESS_FILE, 'r') as f:
                        content = f.read()
                    
                    lines = content.split('\n')
                    # Remove existing RS_HOST_ID, RS_HOST_PRINCIPAL, and RS_HOST_NAME lines
                    lines = [line for line in lines if not line.startswith('RS_HOST_ID=') and not line.startswith('RS_HOST_PRINCIPAL=') and not line.startswith('RS_HOST_NAME=')]
                    # Add new lines
                    lines.append(f'RS_HOST_ID="{selected_server_id}"')
                    lines.append(f'RS_HOST_PRINCIPAL="{server_principal}"')
                    lines.append(f'RS_HOST_NAME="{server_name}"')
                    new_content = '\n'.join(lines)
                    
                    with open(RUMSAN_SSH_ACCESS_FILE, 'w') as f:
                        f.write(new_content)
                    
                    print(f"[OK] Server ID, principal, and name saved to temp file")
                except Exception as e:
                    print(f"[ERROR] Failed to update temp file: {e}")
            
            selected_server = selected_server_id
            
            # Get key_id from temp file and create certificate
            try:
                with open(RUMSAN_SSH_ACCESS_FILE, 'r') as f:
                    content = f.read()
                
                lines = content.split('\n')
                key_id = None
                for line in lines:
                    if line.startswith('RS_KEY_ID='):
                        key_id = line.split('=', 1)[1].strip('"')
                        break
                
                if not key_id:
                    print("[ERROR] RS_KEY_ID not found in temp file")
                else:
                    # Call create-cert API
                    url = SERVER_URL + "/functions/v1/ssh-cert/create-cert"
                    headers = get_api_headers()
                    data = {"key_id": key_id, "host_id": selected_server_id}
                    response = requests.post(url, headers=headers, json=data, timeout=10)
                    
                    if response.status_code == 200:
                        resp_data = response.json()
                        if resp_data.get('success'):
                            cert_data = resp_data['data']
                            cert_id = cert_data['id']
                            cert_content = cert_data['cert']
                            
                            # Create rumsan folder if not exists
                            os.makedirs(RUMSAN_FOLDER_PATH, exist_ok=True)
                            
                            # Save cert to ${host_id}.pub
                            with open(os.path.join(RUMSAN_FOLDER_PATH, f'{selected_server_id}.pub'), 'w') as f:
                                f.write(cert_content)
                            
                            # Save data to ${host_id}.json
                            with open(os.path.join(RUMSAN_FOLDER_PATH, f'{selected_server_id}.json'), 'w') as f:
                                json.dump(cert_data, f, indent=2)
                            
                            print(f"[OK] Certificate created and saved for host: {selected_server_id}")
                        else:
                            print("[ERROR] Failed to create certificate: success false")
                    else:
                        print(f"[ERROR] API call failed: {response.status_code} - {response.text}")
            except Exception as e:
                print(f"[ERROR] Error creating certificate: {e}")
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode())
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass


def get_google_client_id():
    """Fetch Google Client ID from the provided URL"""
    try:
        response = requests.get(GOOGLE_CLIENT_ID_URL, timeout=5)
        response.raise_for_status()
        
        # The response should contain the client ID
        client_id = response.text.strip()
        if not client_id:
            raise ValueError("Empty client ID received")
        
        print(f"[OK] Retrieved Google Client ID: {client_id[:20]}...")
        return client_id
    except Exception as e:
        print(f"[ERROR] Error fetching Google Client ID: {e}")
        return None


def start_callback_server():
    """Start HTTP server to handle OAuth callback"""
    global server
    
    server = HTTPServer(('localhost', 29670), CallbackHandler)
    print("[OK] Callback server started on http://localhost:29670")
    
    # Handle requests in a separate thread
    import threading
    server_thread = threading.Thread(target=lambda: server.serve_forever())
    server_thread.daemon = True
    server_thread.start()
    
    return server_thread


def generate_auth_url(client_id):
    """Generate Google OAuth authentication URL with implicit flow"""
    params = {
        'client_id': client_id,
        'redirect_uri': REDIRECT_URI,
        'response_type': 'id_token',  # Request ID token directly
        'scope': 'openid email profile',
        'nonce': 'random_nonce_string'  # Recommended for implicit flow
    }
    
    auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(params)}"
    return auth_url


def get_user_hosts(id_token):
    """Fetch list of user's hosts from the API"""
    global hosts_data
    try:
        headers = get_api_headers()
        
        response = requests.get(SERVER_URL + "/functions/v1/user-query/my-hosts", headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            hosts_data = data  # Store globally
            return data
        else:
            print(f"[ERROR] Failed to fetch hosts: {response.status_code}")
            print(f"Response: {response.text}")
            return None
    except Exception as e:
        print(f"[ERROR] Error fetching hosts: {e}")
        return None


def show_server_selection_page(id_token, hosts):
    """Display server selection page in browser"""
    # Build the content
    content = '<h2>Select a Server</h2><form id="serverForm"><select id="serverSelect" required><option value="">Choose a server...</option>'
    
    # Add server options - handle both array and object responses
    host_list = []
    if hosts:
        if isinstance(hosts, list):
            host_list = hosts
        elif isinstance(hosts, dict):
            # Check for common response structures
            if 'data' in hosts and isinstance(hosts['data'], list):
                host_list = hosts['data']
                print(f"[OK] Extracted {len(host_list)} hosts from 'data' field")
            elif 'hosts' in hosts and isinstance(hosts['hosts'], list):
                host_list = hosts['hosts']
                print(f"[OK] Extracted {len(host_list)} hosts from 'hosts' field")
            else:
                # If dict but not a known structure, try to use it as is
                host_list = [hosts] if hosts.get('name') or hosts.get('id') else []
                print(f"[WARNING] Using hosts dict directly: {host_list}")
    
    # Sort hosts alphabetically by display name (name [principal])
    host_list = sorted(host_list, key=lambda h: f"{h.get('name', 'Unknown')} [{h.get('principal', 'Unknown')}]")
    
    for host in host_list:
        if isinstance(host, dict):
            host_name = host.get('name', 'Unknown')
            host_principal = host.get('principal', 'Unknown')
            display_name = f"{host_name} [{host_principal}]"
            host_id = host.get('id', '')
            print(f"  Adding option: {display_name} ({host_id})")
            content += f'<option value="{host_id}">{display_name}</option>'
    
    content += '</select><br><button type="submit">Connect</button></form><script>document.addEventListener("DOMContentLoaded", function() { const select = document.getElementById("serverSelect"); const options = select.querySelectorAll("option"); if (options.length === 2 && options[1].value) { select.value = options[1].value; } }); document.getElementById("serverForm").onsubmit = function(e) { e.preventDefault(); const selectedServer = document.getElementById("serverSelect").value; const selectElement = document.getElementById("serverSelect"); const selectedOption = selectElement.options[selectElement.selectedIndex]; const serverName = selectedOption.text; if (selectedServer) { document.body.innerHTML = "<div class=\\"container\\"><h1>Processing...</h1><p>Connecting to server and creating certificate...</p><div style=\\"margin-top: 20px;\\"><div style=\\"border: 4px solid #f3f3f3; border-top: 4px solid #4CAF50; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto;\\"></div></div><style>@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }</style></div>"; fetch("/server-selected", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({server_id: selectedServer}) }).then(response => { if (response.ok) { document.body.innerHTML = "<div class=\\"container\\"><img src=\\"https://avatars.githubusercontent.com/u/102228984?s=1024&v=4\\" alt=\\"Rumsan Logo\\" class=\\"logo\\"><h1>&check; Server is Connected!</h1><h2>" + serverName + "</h2><p class=\\"info-text\\">For the next 7 days you can directly login to this server in terminal using:</p><div class=\\"code-block\\">ssh " + serverName + "</div><p class=\\"info-text\\">You can now close this window and return to the terminal.</p></div>"; } else { alert("Failed to select server. Please try again."); } }).catch(error => { console.error("Error:", error); alert("An error occurred. Please try again."); }); } };</script>'
    
    return generate_html_page("Select Server", content)


def main():
    """Main OAuth login flow"""
    global id_token, selected_server
    
    print("Google OAuth Login with Implicit Flow")
    print("=" * 30)
    
    # Step 0: Start callback server (needed for both auth and server selection)
    print("\n0. Starting callback server...")
    server_thread = start_callback_server()
    time.sleep(0.5)  # Give server time to start
    
    # Step 1: Check for existing valid token
    print("\n1. Checking for existing valid token...")
    cached_token = load_token_from_file()
    if cached_token:
        id_token = cached_token
        print("[OK] Using cached token, skipping login...")
    else:
        id_token = None
    
    # Step 2: Try to fetch hosts with current token
    if id_token:
        print("\n2. Fetching available servers...")
        hosts = get_user_hosts(id_token)
        if hosts is not None:
            # Token is valid and hosts fetched successfully
            print("[OK] Successfully fetched servers with cached token")
            server_selection_url = "http://localhost:29670/server-selection"
            webbrowser.open(server_selection_url)
            print(f"   Opening: {server_selection_url}")
        else:
            # Token might be invalid even though not expired, need to re-authenticate
            print("[WARNING] Failed to fetch hosts with cached token, re-authenticating...")
            id_token = None
    
    # If no valid token or host fetch failed, perform OAuth login
    if id_token is None:
        # Fetch Google Client ID dynamically
        print("\n2. Fetching Google Client ID...")
        client_id = get_google_client_id()
        if not client_id:
            print("Failed to get Google Client ID. Exiting.")
            return
        
        # Generate and open auth URL
        print("\n3. Opening Google login in browser...")
        auth_url = generate_auth_url(client_id)
        webbrowser.open(auth_url)
        print(f"   Opening: {auth_url[:80]}...")
        
        # Wait for callback with ID token
        print("\n4. Waiting for authentication...")
        timeout = 120  # 2 minutes timeout
        start_time = time.time()
        
        while id_token is None and (time.time() - start_time) < timeout:
            time.sleep(0.5)
        
        if id_token is None:
            print("[ERROR] Authentication timeout. No ID token received.")
            return
        
        print("[OK] ID token received successfully!")
        
        # Open server selection page
        print("\n5. Opening server selection page in browser...")
        server_selection_url = "http://localhost:29670/server-selection"
        webbrowser.open(server_selection_url)
        print(f"   Opening: {server_selection_url}")
    
    # Step 5: Wait for server selection
    print("\n5. Waiting for server selection...")
    start_time = time.time()
    timeout = 120  # 2 minutes timeout
    
    while selected_server is None and (time.time() - start_time) < timeout:
        time.sleep(0.5)
    
    if selected_server is None:
        print("[ERROR] Server selection timeout.")
        return
    
    print("[OK] Server selected successfully!")
    
    # Shutdown server
    if server:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[INFO] Authentication cancelled by user.")
        if server:
            server.server_close()
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        if server:
            server.server_close()
