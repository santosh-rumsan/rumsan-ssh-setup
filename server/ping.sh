#!/bin/bash

# Meta file to store configuration values
RUMSAN_PATH="/etc/ssh/rumsan"
META_FILE="$RUMSAN_PATH/meta.sh"

BASE_URL="https://ceamyckytvqemsjijavg.supabase.co/functions/v1"

# Setup dependencies
setup_dependencies() {
    if ! python3 -c "from coincurve import PrivateKey; from eth_keys import keys" 2>/dev/null; then
        echo "[INFO] Installing required Python packages..."
        
        # Try normal installation first
        if pip3 install --user coincurve eth-keys > /dev/null 2>&1; then
            echo "[INFO] Dependencies installed successfully"
        # If that fails due to PEP 668, try with --break-system-packages
        elif pip3 install --user --break-system-packages coincurve eth-keys > /dev/null 2>&1; then
            echo "[INFO] Dependencies installed successfully (system packages mode)"
        else
            echo "[ERROR] Failed to install required packages:"
            echo "[ERROR]   pip3 install --user coincurve eth-keys"
            echo "[ERROR]   OR: pip3 install --break-system-packages coincurve eth-keys"
            exit 1
        fi
    fi
}

# Function to read from meta
read_meta() {
    local key=$1
    if [[ -f "$META_FILE" ]]; then
        grep "^${key}=" "$META_FILE" | cut -d'=' -f2-
    fi
}

# Function to sign timestamp with private key using ECDSA
sign_with_private_key() {
    local private_key="$1"
    local timestamp="$2"

    python3 -c "
import sys
import hashlib
try:
    from coincurve import PrivateKey
    from eth_keys import keys
except ImportError as e:
    print(f'Error: Required packages not found. Please install them first:', file=sys.stderr)
    print(f'  pip3 install --user coincurve eth-keys', file=sys.stderr)
    print(f'  OR: pip3 install --break-system-packages coincurve eth-keys', file=sys.stderr)
    sys.exit(1)

private_key = '$private_key'
timestamp = '$timestamp'

# Remove 0x prefix if present
priv_key_hex = private_key.replace('0x', '')

# Use eth_keys for Ethereum-compatible signing
pk_bytes = bytes.fromhex(priv_key_hex)
pk = keys.PrivateKey(pk_bytes)

# Hash the timestamp with SHA-256
message_hash = hashlib.sha256(timestamp.encode('utf-8')).digest()

# Sign and get recoverable signature
signature = pk.sign_msg_hash(message_hash)

# Convert to hex format: 0x + r(64 chars) + s(64 chars) + v(2 chars)
# signature is a SignableMessage with vrs attribute
sig_hex = signature.to_hex()

# Return as hex string
print(sig_hex)
"
}

# Get HOST_PRIVATE_KEY from meta file
echo "[INFO] Setting up dependencies..."
setup_dependencies

HOST_PRIVATE_KEY=$(read_meta "HOST_PRIVATE_KEY")

# Check if credentials exist
if [[ -z "$HOST_PRIVATE_KEY" ]]; then
    echo "[ERROR] HOST_PRIVATE_KEY not found in meta file"
    echo "Please run rs_setup_server.sh first to initialize the server"
    exit 1
fi

# Check if hosts.json exists
HOSTS_FILE="$RUMSAN_PATH/hosts.json"
if [[ ! -f "$HOSTS_FILE" ]]; then
    echo "[ERROR] hosts.json not found at $HOSTS_FILE"
    exit 1
fi

# Function to ping a single host
ping_host() {
    local host_id="$1"
    local hostname="$2"
    local username="$3"
    
    # Generate timestamp
    TIMESTAMP_SECONDS=$(date +%s)
    TIMESTAMP=$((TIMESTAMP_SECONDS * 1000))

    echo "[INFO] Pinging host: $hostname ($username) with ID: $host_id"

    # Sign the timestamp with HOST_PRIVATE_KEY
    SIGNATURE=$(sign_with_private_key "$HOST_PRIVATE_KEY" "$TIMESTAMP")

    # Create JSON payload
    PAYLOAD=$(cat <<EOF
{
  "signature":"$SIGNATURE",
  "timestamp":"$TIMESTAMP",
  "host_id":"$host_id"
}
EOF
    )

    # Send POST request to the API
    RESPONSE=$(curl -s -X POST "$BASE_URL/host/ping" \
      -H "Content-Type: application/json" \
      -d "$PAYLOAD")

    # Parse response
    if echo "$RESPONSE" | grep -q "error"; then
        echo "[ERROR] API returned an error for [$hostname]"
        # Try to extract error or message from JSON response
        ERROR_MSG=$(echo "$RESPONSE" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('error') or data.get('message', ''))" 2>/dev/null)
        if [[ -n "$ERROR_MSG" ]]; then
            echo "[ERROR] $ERROR_MSG"
        else
            echo "[ERROR] $RESPONSE"
        fi
        return 1
    else
        echo "[SUCCESS] Ping sent successfully for [$hostname]"
        return 0
    fi
}

# Read hosts.json and ping each host
echo "[INFO] Reading hosts from $HOSTS_FILE"

# Counter for success/failure
SUCCESS_COUNT=0
FAILURE_COUNT=0
TOTAL_COUNT=0

# Parse and iterate through hosts using jq
if command -v jq &> /dev/null; then
    # Use jq if available
    while IFS= read -r line; do
        host_id=$(echo "$line" | jq -r '.host_id')
        hostname=$(echo "$line" | jq -r '.hostname')
        username=$(echo "$line" | jq -r '.username')
        
        TOTAL_COUNT=$((TOTAL_COUNT + 1))
        
        if ping_host "$host_id" "$hostname" "$username"; then
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        else
            FAILURE_COUNT=$((FAILURE_COUNT + 1))
        fi
    done < <(jq -c '.[]' "$HOSTS_FILE")
else
    # Fallback: use python3 if jq is not available
    python3 << 'PYTHON_EOF'
import json
import subprocess
import os

hosts_file = os.environ.get('HOSTS_FILE')
with open(hosts_file, 'r') as f:
    hosts = json.load(f)

for host in hosts:
    host_id = host['host_id']
    hostname = host['hostname']
    username = host['username']
    print(f"[INFO] Pinging host: {hostname} ({username}) with ID: {host_id}")
PYTHON_EOF
fi

# Print summary
echo ""
echo "[SUMMARY] Total hosts: $TOTAL_COUNT"
echo "[SUMMARY] Successful pings: $SUCCESS_COUNT"
echo "[SUMMARY] Failed pings: $FAILURE_COUNT"

# Exit with error if any pings failed
if [[ $FAILURE_COUNT -gt 0 ]]; then
    exit 1
fi