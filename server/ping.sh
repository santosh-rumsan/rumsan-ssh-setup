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

# Get HOST_PRIVATE_KEY and HOST_ID from meta file
echo "[INFO] Setting up dependencies..."
setup_dependencies

HOST_PRIVATE_KEY=$(read_meta "HOST_PRIVATE_KEY")
HOST_ID=$(read_meta "HOST_ID")

# Check if credentials exist
if [[ -z "$HOST_PRIVATE_KEY" ]]; then
    echo "[ERROR] HOST_PRIVATE_KEY not found in meta file"
    echo "Please run rs_setup_server.sh first to initialize the server"
    exit 1
fi

if [[ -z "$HOST_ID" ]]; then
    echo "[ERROR] HOST_ID not found in meta file"
    echo "Please run rs_setup_server.sh first to initialize the server"
    exit 1
fi

# Generate timestamp
TIMESTAMP_SECONDS=$(date +%s)
TIMESTAMP=$((TIMESTAMP_SECONDS * 1000))

echo "[INFO] Generating signature for timestamp: $TIMESTAMP"

# Sign the timestamp with HOST_PRIVATE_KEY
SIGNATURE=$(sign_with_private_key "$HOST_PRIVATE_KEY" "$TIMESTAMP")

echo "[INFO] Timestamp: $TIMESTAMP"
echo "[INFO] Host ID: $HOST_ID"
echo "[INFO] Signature: $SIGNATURE"

# Create JSON payload
PAYLOAD=$(cat <<EOF
{
  "signature":"$SIGNATURE",
  "timestamp":"$TIMESTAMP",
  "host_id":"$HOST_ID"
}
EOF
)

echo "[INFO] Sending ping request to $BASE_URL/host/ping"

# Send POST request to the API
RESPONSE=$(curl -s -X POST "$BASE_URL/host/ping" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

# echo "[INFO] Response: $RESPONSE"

# Parse response
if echo "$RESPONSE" | grep -q "error"; then
    echo "[ERROR] API returned an error"
    exit 1
else
    echo "[SUCCESS] Ping sent successfully"
fi